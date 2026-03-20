// Parent-side sandbox executor — manages the full lifecycle of running
// generated code in a permission-restricted child process.

import { fork, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { attachToolkitHost, attachStubToolkitHost, type ToolkitHostOptions } from "./toolkit-host";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SandboxResult = {
  success: boolean;
  result?: { caught: boolean; reason: string; sideEffects?: Record<string, unknown> };
  error?: string;
  timedOut?: boolean;
  logs: string[];
  durationMs: number;
};

export interface ExecutorOptions {
  targetUrl?: string;
  agentIdentity?: {
    identityId: string;
    publicKey: string;
    privateKey: string;
  };
  restKey?: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CHILD_RUNNER_SOURCE = path.resolve(__dirname, "child-runner.js");
const TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------------------
// Main function
// ---------------------------------------------------------------------------

export async function executeInSandbox(code: string, options?: ExecutorOptions): Promise<SandboxResult> {
  const startTime = Date.now();
  const logs: string[] = [];
  let tempDir: string | undefined;

  try {
    // Step 1: Create temp directory and resolve symlinks (macOS: /var → /private/var)
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-004-sandbox-"));
    const realTempDir = fs.realpathSync(tempDir);

    // Step 2: Copy child runner into temp directory (use realpath for all paths)
    const childRunnerDest = path.join(realTempDir, "child-runner.js");
    fs.copyFileSync(CHILD_RUNNER_SOURCE, childRunnerDest);

    // Step 3: Spawn child process with permission flags
    const result = await new Promise<SandboxResult>((resolve) => {
      let settled = false;

      function settle(r: SandboxResult) {
        if (!settled) {
          settled = true;
          resolve(r);
        }
      }

      let child: ChildProcess;
      try {
        child = fork(childRunnerDest, [], {
          env: { NODE_ENV: "sandbox" },
          execArgv: [
            "--permission",
            "--allow-fs-read=" + realTempDir,
          ],
          stdio: ["pipe", "pipe", "pipe", "ipc"],
        });
      } catch (err) {
        settle({
          success: false,
          error: `Failed to spawn child process: ${err instanceof Error ? err.message : String(err)}`,
          logs,
          durationMs: Date.now() - startTime,
        });
        return;
      }

      // Attach toolkit host — real HTTP if options provided, stubs otherwise
      if (options?.targetUrl && options?.agentIdentity && options?.restKey) {
        attachToolkitHost(child, {
          targetUrl: options.targetUrl,
          agentIdentity: options.agentIdentity,
          restKey: options.restKey,
        });
      } else {
        attachStubToolkitHost(child);
      }

      // Step 4: Set up 15-second hard timeout
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        settle({
          success: false,
          timedOut: true,
          error: `Sandbox execution timed out after ${TIMEOUT_MS / 1000}s`,
          logs,
          durationMs: Date.now() - startTime,
        });
      }, TIMEOUT_MS);

      // Step 5: Collect logs and results via IPC
      child.on("message", (msg: unknown) => {
        const m = msg as Record<string, unknown>;
        if (!m || typeof m !== "object") return;

        // toolkit-request messages are handled by the attached host — skip here
        if (m.type === "toolkit-request") return;

        if (m.type === "log" && typeof m.message === "string") {
          logs.push(m.message);
          return;
        }

        if (m.type === "result") {
          clearTimeout(timer);
          child.kill();
          settle({
            success: true,
            result: m.result as SandboxResult["result"],
            logs,
            durationMs: Date.now() - startTime,
          });
          return;
        }

        if (m.type === "error") {
          clearTimeout(timer);
          child.kill();
          settle({
            success: false,
            error: typeof m.error === "string" ? m.error : "Unknown error from child",
            logs,
            durationMs: Date.now() - startTime,
          });
          return;
        }
      });

      // Step 7: Handle child events
      child.on("error", (err) => {
        clearTimeout(timer);
        settle({
          success: false,
          error: `Child process error: ${err.message}`,
          logs,
          durationMs: Date.now() - startTime,
        });
      });

      child.on("exit", (exitCode, signal) => {
        clearTimeout(timer);
        settle({
          success: false,
          error: `Child process exited unexpectedly (code: ${exitCode}, signal: ${signal})`,
          logs,
          durationMs: Date.now() - startTime,
        });
      });

      // Step 6: Send the code to execute
      child.send({ type: "execute", code });
    });

    return result;
  } catch (err) {
    return {
      success: false,
      error: `Executor error: ${err instanceof Error ? err.message : String(err)}`,
      logs,
      durationMs: Date.now() - startTime,
    };
  } finally {
    // Step 9: Cleanup temp directory
    if (tempDir) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // Best effort cleanup
      }
    }
  }
}
