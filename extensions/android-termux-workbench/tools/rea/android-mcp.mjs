// Controlled REA Android-provider entry used by the local static-analysis adapter.
import { realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "../../run/rea-3a0be4d8/released/node_modules/@modelcontextprotocol/client/dist/index.mjs";
import { StdioClientTransport } from "../../run/rea-3a0be4d8/released/node_modules/@modelcontextprotocol/client/dist/stdio.mjs";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sampleRoot = path.join(projectRoot, "run/rea-b06dd042");
const target = await realpath(process.argv[2] ?? "");
const requestedTimeoutMs = Number.parseInt(process.argv[3] ?? "180000", 10);
if (!Number.isSafeInteger(requestedTimeoutMs) || requestedTimeoutMs < 30_000 || requestedTimeoutMs > 900_000)
  throw new Error("INVALID_TIMEOUT");
const timeoutMs = requestedTimeoutMs;
const allowedRoots = [
  await realpath(path.join(sampleRoot, "samples")),
  await realpath(path.join(sampleRoot, "inbox")).catch(() => path.join(sampleRoot, "inbox")),
];
const jobsRoot = await realpath(path.join(sampleRoot, "jobs")).catch(() => path.join(sampleRoot, "jobs"));
const jobsRelative = path.relative(jobsRoot, target);
const generatedApksUnit = !jobsRelative.startsWith("..") && !path.isAbsolute(jobsRelative)
  && jobsRelative.split(path.sep).length === 3
  && jobsRelative.split(path.sep)[1] === "apks-units"
  && target.endsWith(".apk");
if (!allowedRoots.some((root) => target.startsWith(`${root}/`)) && !generatedApksUnit)
  throw new Error("TARGET_DENIED");
if ((await stat(target)).size > 512 * 1024 * 1024)
  throw new Error("TARGET_TOO_LARGE");

const client = new Client(
  { name: "rea-termux-android-static-adapter", version: "1.1.0" },
  { capabilities: {} },
);
const transport = new StdioClientTransport({
  command: path.join(projectRoot, "bin/rea-termux"),
  args: ["mcp"],
  cwd: sampleRoot,
  env: process.env,
  stderr: "pipe",
  maxBufferSize: 16 * 1024 * 1024,
});
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr += chunk.toString();
});
try {
  await client.connect(transport, { timeout: Math.min(timeoutMs, 60_000) });
  const session = await client.callTool(
    { name: "binary_session", arguments: { expected_package_version: "6.3.0" } },
    undefined,
    { timeout: Math.min(timeoutMs, 90_000) },
  );
  if (session.isError === true) throw new Error("BINARY_SESSION_FAILED");
  const inspected = await client.callTool(
    { name: "inspect_android_package", arguments: { path: target } },
    undefined,
    { timeout: timeoutMs },
  );
  if (inspected.isError === true) throw new Error("ANDROID_INSPECTION_FAILED");
  const classes = await client.callTool(
    { name: "search_android_classes", arguments: { path: target, query: "" } },
    undefined,
    { timeout: timeoutMs },
  );
  if (classes.isError === true) throw new Error("ANDROID_CLASS_INVENTORY_FAILED");
  process.stdout.write(
    `${JSON.stringify({
      server: client.getServerVersion(),
      provider: "rea-android-jadx",
      target,
      timeout_ms: timeoutMs,
      package_evidence: inspected.structuredContent,
      class_inventory_evidence: classes.structuredContent,
    })}\n`,
  );
} catch (error) {
  if (stderr) process.stderr.write(stderr);
  throw error;
} finally {
  await client.close().catch(() => {});
  await transport.close().catch(() => {});
}
