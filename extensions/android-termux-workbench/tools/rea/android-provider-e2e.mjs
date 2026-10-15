// Real REA Android-provider acceptance probe for the Termux compatibility patch.
// The target APK is an owned fixture and is never executed.
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "../../run/rea-3a0be4d8/released/node_modules/@modelcontextprotocol/client/dist/index.mjs";
import { StdioClientTransport } from "../../run/rea-3a0be4d8/released/node_modules/@modelcontextprotocol/client/dist/stdio.mjs";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sourceRoot = path.join(projectRoot, "run/rea-3a0be4d8/upstream");
const fixtureRoot = path.join(projectRoot, "run/rea-b06dd042");
const runRoot = path.join(projectRoot, "run/rea-termux-android-provider");
const evidenceRoot = path.join(runRoot, "evidence");
const apkPath = path.join(fixtureRoot, "samples/owned.apk");
const jadxJar = path.join(fixtureRoot, "c1/jadx-headless-mcp-0.7.1-all.jar");
const stderrPath = path.join(evidenceRoot, "mcp.stderr.log");
const resultsPath = path.join(evidenceRoot, "android-provider-e2e.json");

await mkdir(path.join(runRoot, "home"), { recursive: true });
await mkdir(path.join(runRoot, "tmp"), { recursive: true });
await mkdir(evidenceRoot, { recursive: true });

const sha256 = async (file) =>
  createHash("sha256").update(await readFile(file)).digest("hex");
const calls = [];
const record = {
  task: "REA_TERMUX_ANDROID_PROVIDER_UPGRADE",
  platform: process.platform,
  arch: process.arch,
  source_revision: "6543405252d7c740c87a3bb433cf666187af41fa",
  status: "FAILED",
  apk: { path: apkPath, sha256: await sha256(apkPath) },
  jadx: { path: jadxJar, sha256: await sha256(jadxJar) },
  calls,
};

const client = new Client(
  { name: "rea-termux-android-provider-e2e", version: "1.0.0" },
  { capabilities: {} },
);
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.join(sourceRoot, "scripts/rea.mjs"), "mcp"],
  cwd: runRoot,
  env: {
    ...process.env,
    HOME: path.join(runRoot, "home"),
    TMPDIR: path.join(runRoot, "tmp"),
    JAVA_HOME: "/data/data/com.termux/files/usr/lib/jvm/java-21-openjdk",
    REA_JADX_MCP_JAR: jadxJar,
    REA_JADX_HEAP_MIB: "384",
    REA_JADX_ACTIVE_PROCESSOR_COUNT: "1",
    REA_MCP_INPUT_SCHEMA_PROFILE: "compact",
  },
  stderr: "pipe",
  maxBufferSize: 16 * 1024 * 1024,
});

let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr += chunk.toString();
});

const call = async (name, args, timeout = 60_000) => {
  const started = Date.now();
  const result = await client.callTool(
    { name, arguments: args },
    undefined,
    { timeout },
  );
  calls.push({
    name,
    arguments: args,
    duration_ms: Date.now() - started,
    isError: result.isError === true,
    structuredContent: result.structuredContent ?? null,
    content: result.content,
  });
  if (result.isError === true)
    throw new Error(`${name} returned an MCP tool error`);
  return result;
};

try {
  await client.connect(transport, { timeout: 30_000 });
  record.server = client.getServerVersion();
  const catalog = await client.listTools(undefined, { timeout: 30_000 });
  record.catalog = catalog.tools.map(({ name }) => name);
  for (const expected of [
    "inspect_android_package",
    "search_android_classes",
    "inspect_android_class",
    "inspect_android_method",
  ]) {
    if (!record.catalog.includes(expected))
      throw new Error(`missing tool ${expected}`);
  }

  await call("binary_session", { expected_package_version: "6.3.0" });
  const inspected = await call("inspect_android_package", { path: apkPath });
  const searched = await call("search_android_classes", {
    path: apkPath,
    query: "OwnedArithmetic",
  });
  const classResult = await call("inspect_android_class", {
    path: apkPath,
    class_name: "owned.acceptance.OwnedArithmetic",
  });
  const methodResult = await call("inspect_android_method", {
    path: apkPath,
    class_name: "owned.acceptance.OwnedArithmetic",
    method_name: "add",
  });

  const packageData = inspected.structuredContent?.normalized_result;
  const searchData = searched.structuredContent?.normalized_result;
  const classData = classResult.structuredContent?.normalized_result;
  const methodData = methodResult.structuredContent?.normalized_result;
  if (!packageData || packageData.class_count < 1)
    throw new Error("package inspection returned no classes");
  if (!searchData?.matches?.includes("owned.acceptance.OwnedArithmetic"))
    throw new Error("owned class was not found");
  if (classData?.class_name !== "owned.acceptance.OwnedArithmetic")
    throw new Error("class inspection identity mismatch");
  if (methodData?.method?.name !== "add" || methodData.body_status !== "available")
    throw new Error("method decompilation was not available");

  record.status = "VERIFIED";
  record.verification = {
    class_count: packageData.class_count,
    package_name: packageData.package_name,
    engine: packageData.engine,
    matched_class: searchData.matches[0],
    method_representation: methodData.representation,
    method_body_status: methodData.body_status,
  };
} catch (error) {
  record.error = error instanceof Error ? error.stack ?? error.message : String(error);
  process.exitCode = 1;
} finally {
  const childPid = transport.pid;
  await client.close().catch(() => {});
  await transport.close().catch(() => {});
  record.server_pid = childPid ?? null;
  if (childPid) {
    try {
      process.kill(childPid, 0);
      record.server_alive_after_close = true;
      record.status = "FAILED";
      record.error = "REA server remained alive after close";
      process.exitCode = 1;
    } catch (error) {
      record.server_alive_after_close = error?.code !== "ESRCH";
    }
  }
  await writeFile(stderrPath, stderr);
  await writeFile(resultsPath, `${JSON.stringify(record, null, 2)}\n`);
  process.stdout.write(
    `${JSON.stringify({
      status: record.status,
      calls: record.calls.map(({ name, duration_ms, isError }) => ({
        name,
        duration_ms,
        isError,
      })),
      verification: record.verification ?? null,
      evidence: resultsPath,
    })}\n`,
  );
}
