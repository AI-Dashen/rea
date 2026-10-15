#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index === -1 || index + 1 >= process.argv.length) {
    throw new Error(`MISSING_ARGUMENT:${name}`);
  }
  return process.argv[index + 1];
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

const moduleRoot = path.resolve(argument("--module-root"));
const endpoint = argument("--endpoint");
const packageName = argument("--package");
const pid = Number.parseInt(argument("--pid"), 10);
const outputPath = path.resolve(argument("--output"));

if (!/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(packageName)) {
  throw new Error("INVALID_PACKAGE");
}
if (!Number.isSafeInteger(pid) || pid <= 1) {
  throw new Error("INVALID_PID");
}
if (packageName === "android" || packageName.startsWith("com.android.")) {
  throw new Error("SYSTEM_TARGET_DENIED");
}

const bindingPath = path.join(moduleRoot, "build", "frida_binding.node");
const wrapperPath = path.join(moduleRoot, "build", "src", "frida.js");
const result = {
  schema_version: 1,
  status: "FAILED",
  endpoint,
  package: packageName,
  pid,
  binding: {
    path: bindingPath,
    bytes: fs.statSync(bindingPath).size,
    sha256: sha256(bindingPath),
  },
  process_enumeration: "PENDING",
  attach: "PENDING",
  script_load: "PENDING",
  detach: "PENDING",
};

let manager;
let device;
let session;
let script;
try {
  process.chdir(moduleRoot);
  const frida = await import(pathToFileURL(wrapperPath).href);
  manager = frida.getDeviceManager();
  device = await manager.addRemoteDevice(endpoint);

  const processes = await device.enumerateProcesses();
  result.process_enumeration = "PASS";
  result.process_count = processes.length;
  const target = processes.find((item) => item.pid === pid);
  if (!target) {
    throw new Error("TARGET_PID_NOT_ENUMERATED");
  }
  // Android Frida servers may report the application label here instead of
  // the Linux cmdline/package. The privileged launcher must validate UID,
  // PID and /proc/<pid>/cmdline before invoking this probe.
  result.enumerated_target = { pid: target.pid, name: target.name };

  session = await device.attach(pid);
  result.attach = "PASS";
  result.session_pid = session.pid;

  script = await session.createScript(`
    rpc.exports = {
      probe() {
        return {
          pid: Process.id,
          arch: Process.arch,
          platform: Process.platform,
          pointer_size: Process.pointerSize,
          page_size: Process.pageSize
        };
      }
    };
  `);
  await script.load();
  result.script_load = "PASS";
  const rawAgent = await script.exports.probe();
  let normalizedAgent = rawAgent;
  if (typeof rawAgent === "string") {
    const envelope = JSON.parse(rawAgent);
    if (envelope?.type === "send" && Array.isArray(envelope.payload)
        && envelope.payload[0] === "frida:rpc" && envelope.payload[2] === "ok") {
      normalizedAgent = envelope.payload[3];
      result.rpc_wrapper_compatibility = "JSON_STRING_ENVELOPE_NORMALIZED";
    }
  }
  result.agent = normalizedAgent;
  if (result.agent.pid !== pid) {
    throw new Error("AGENT_PID_MISMATCH");
  }

  await script.unload();
  script = null;
  await session.detach();
  session = null;
  result.detach = "PASS";
  result.status = "PASS";
} catch (error) {
  result.error = error instanceof Error ? error.message : String(error);
  process.exitCode = 1;
} finally {
  if (script !== undefined && script !== null) {
    try { await script.unload(); } catch {}
  }
  if (session !== undefined && session !== null) {
    try { await session.detach(); } catch {}
  }
  if (manager !== undefined && device !== undefined) {
    try { await manager.removeRemoteDevice(endpoint); } catch {}
  }
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
