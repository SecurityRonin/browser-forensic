#!/usr/bin/env bun

import { spawn } from "bun";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const promptPath = join(scriptDir, "prompt.md");

const { values } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    "max-iterations": { type: "string", default: "100" },
    prompt: { type: "string" },
  },
});

async function runRalph() {
  const baselinePrompt = await Bun.file(promptPath).text();

  const prompt = values.prompt
    ? `${values.prompt}\n\n---\n\n${baselinePrompt}`
    : baselinePrompt;

  const maxIterations = values["max-iterations"] || "100";

  const escapedPrompt = prompt.replace(/'/g, "'\\''");

  console.log("[runner] Starting Ralph loop via Claude Code...\n");
  console.log(`[runner] Max iterations: ${maxIterations}\n`);

  const proc = spawn({
    cmd: [
      "claude",
      "--permission-mode", "bypassPermissions",
      "--verbose",
      `${escapedPrompt}`,
    ],
    stdout: "inherit",
    stderr: "inherit",
    stdin: "inherit",
    env: {
      ...process.env,
      GITSIGN_CREDENTIAL_CACHE: `${process.env.HOME}/Library/Caches/sigstore/gitsign/cache.sock`,
    },
    cwd: join(scriptDir, "../.."),
  });

  await proc.exited;

  const exitCode = proc.exitCode ?? 0;
  if (exitCode === 0) {
    console.log("\n[runner] Ralph loop completed successfully!");
  } else {
    console.log(`\n[runner] Ralph loop exited with code ${exitCode}`);
  }

  process.exit(exitCode);
}

runRalph().catch((err) => {
  console.error("[runner] Error:", err);
  process.exit(1);
});
