#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

function argument(name, fallback = null) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

function sha256(file) {
  return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

const moduleRoot = path.resolve(argument("--module-root", process.cwd()));
const endpoint = argument("--endpoint");
const enumerateProcesses = process.argv.includes("--enumerate-processes");
const bindingPath = path.join(moduleRoot, "build", "frida_binding.node");
const wrapperPath = path.join(moduleRoot, "build", "src", "frida.js");
const result = {
  schema_version: 1,
  module_root: moduleRoot,
  binding: { path: bindingPath, exists: fs.existsSync(bindingPath) },
  wrapper: { path: wrapperPath, exists: fs.existsSync(wrapperPath) },
  status: "FAILED",
};

try {
  if (!result.binding.exists || !result.wrapper.exists) {
    throw new Error("FRIDA_RUNTIME_INCOMPLETE");
  }
  result.binding.bytes = fs.statSync(bindingPath).size;
  result.binding.sha256 = sha256(bindingPath);
  process.chdir(moduleRoot);
  const frida = await import(pathToFileURL(wrapperPath).href);
  const manager = frida.getDeviceManager();
  const devices = endpoint
    ? [await manager.addRemoteDevice(endpoint)]
    : await manager.enumerateDevices();
  result.binding_load = "PASS";
  result.endpoint = endpoint;
  result.devices = devices.map((device) => ({
    id: device.id,
    name: device.name,
    type: device.type,
  }));
  if (enumerateProcesses) {
    const processes = await devices[0].enumerateProcesses();
    result.process_enumeration = "PASS";
    result.process_count = processes.length;
  }
  result.status = "PASS";
} catch (error) {
  result.error = error instanceof Error ? error.message : String(error);
  process.exitCode = 1;
}
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
