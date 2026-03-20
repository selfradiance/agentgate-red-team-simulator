// child-runner.js — Sandboxed execution environment for novel attack code.
//
// This file runs directly via `node` (not tsx) with permission flags that restrict
// filesystem, child process, and worker access. Before any generated code executes,
// dangerous globals are deleted from the V8 context so the generated code cannot
// access the network, filesystem, timers, or process information.
//
// The child process is logic-only. All HTTP calls go through an IPC-based toolkit
// that sends messages to the parent process, which owns all network access.

"use strict";

// ---------------------------------------------------------------------------
// Step 1: Capture essentials before we delete everything
// ---------------------------------------------------------------------------

const _send = process.send.bind(process);
const _on = process.on.bind(process);
const _Function = Function;

// ---------------------------------------------------------------------------
// Step 2: Delete dangerous globals
// ---------------------------------------------------------------------------

// Network / IO
delete globalThis.fetch;
delete globalThis.XMLHttpRequest;
delete globalThis.WebSocket;
delete globalThis.Blob;
delete globalThis.URL;
delete globalThis.URLSearchParams;

// Module system
delete globalThis.require;
delete globalThis.module;
delete globalThis.exports;

// Process (captured _send and _on above)
delete globalThis.process;

// Code generation / eval
delete globalThis.eval;
delete globalThis.Function;

// Timers
delete globalThis.setTimeout;
delete globalThis.setInterval;
delete globalThis.setImmediate;
delete globalThis.queueMicrotask;

// ---------------------------------------------------------------------------
// Step 3: Set up IPC-based toolkit
// ---------------------------------------------------------------------------

let _requestId = 0;
const _pending = new Map(); // id → { resolve, reject }
let _createIdentityCount = 0;

// IPC round-trip: send request to parent, wait for matching response
function _toolkitCall(method, args) {
  const id = ++_requestId;
  return new Promise((resolve, reject) => {
    _pending.set(id, { resolve, reject });
    _send({ type: "toolkit-request", id, method, args });
  });
}

const toolkit = {
  async signedPost(path, body) {
    return _toolkitCall("signedPost", [path, body]);
  },

  async rawPost(path, body, headers) {
    return _toolkitCall("rawPost", [path, body, headers]);
  },

  async rawGet(path) {
    return _toolkitCall("rawGet", [path]);
  },

  async createIdentity() {
    _createIdentityCount++;
    if (_createIdentityCount > 3) {
      throw new Error("createIdentity() cap exceeded: maximum 3 identities per attack execution");
    }
    return _toolkitCall("createIdentity", []);
  },

  async signedPostAs(identity, path, body) {
    return _toolkitCall("signedPostAs", [identity, path, body]);
  },

  async sleep(ms) {
    const capped = Math.min(ms, 5000);
    return new Promise((resolve) => {
      const end = Date.now() + capped;
      function check() {
        if (Date.now() >= end) {
          resolve();
        } else {
          Promise.resolve().then(check);
        }
      }
      check();
    });
  },

  async getReputation(identityId) {
    return _toolkitCall("getReputation", [identityId]);
  },

  async getBondStatus(bondId) {
    return _toolkitCall("getBondStatus", [bondId]);
  },

  async getActionStatus(actionId) {
    return _toolkitCall("getActionStatus", [actionId]);
  },

  async checkDashboardForRawHtml() {
    return _toolkitCall("checkDashboardForRawHtml", []);
  },

  log(message) {
    _send({ type: "log", message: String(message) });
  },
};

Object.freeze(toolkit);

// ---------------------------------------------------------------------------
// Step 4: Listen for messages from parent via IPC
// Handles both "execute" (code to run) and "toolkit-response/toolkit-error" (IPC responses)
// ---------------------------------------------------------------------------

_on("message", async (msg) => {
  if (!msg || typeof msg !== "object") return;

  // Handle toolkit responses from parent
  if (msg.type === "toolkit-response" && typeof msg.id === "number") {
    const pending = _pending.get(msg.id);
    if (pending) {
      _pending.delete(msg.id);
      pending.resolve(msg.result);
    }
    return;
  }

  if (msg.type === "toolkit-error" && typeof msg.id === "number") {
    const pending = _pending.get(msg.id);
    if (pending) {
      _pending.delete(msg.id);
      pending.reject(new Error(msg.error || "Unknown toolkit error"));
    }
    return;
  }

  // Handle execute command
  if (msg.type === "execute" && typeof msg.code === "string") {
    try {
      const fn = new _Function("toolkit", msg.code + "\nreturn novelAttack(toolkit);");
      const result = await fn(toolkit);
      _send({ type: "result", result });
    } catch (err) {
      _send({ type: "error", error: err instanceof Error ? err.message : String(err) });
    }
    return;
  }
});
