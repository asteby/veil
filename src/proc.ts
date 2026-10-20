import { spawn } from 'node:child_process';

export interface RunOptions {
  /** Data written to the child's stdin then closed. Secrets travel ONLY this way (or via env). */
  stdin?: string | Buffer;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export interface RunResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: Buffer;
  stderr: Buffer;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  timedOut: boolean;
}

/** Function signature used everywhere we spawn processes; injectable for tests. */
export type Runner = (argv: string[], opts?: RunOptions) => Promise<RunResult>;

/**
 * Runs argv WITHOUT a shell. Output beyond maxOutputBytes is discarded (the child
 * keeps running until it exits or times out). Never logs argv, stdin or output.
 */
export const run: Runner = (argv, opts = {}) =>
  new Promise((resolve, reject) => {
    const [cmd, ...args] = argv;
    if (!cmd) return reject(new Error('empty argv'));
    const max = opts.maxOutputBytes ?? 1024 * 1024;
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: opts.env ?? process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
      windowsHide: true,
      detached: process.platform !== 'win32',
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let outLen = 0;
    let errLen = 0;
    let outTrunc = false;
    let errTrunc = false;
    let timedOut = false;
    child.stdout.on('data', (d: Buffer) => {
      if (outLen < max) {
        const take = d.subarray(0, max - outLen);
        out.push(take);
        outLen += take.length;
        if (take.length < d.length) outTrunc = true;
      } else outTrunc = true;
    });
    child.stderr.on('data', (d: Buffer) => {
      if (errLen < max) {
        const take = d.subarray(0, max - errLen);
        err.push(take);
        errLen += take.length;
        if (take.length < d.length) errTrunc = true;
      } else errTrunc = true;
    });
    const killTree = () => {
      try {
        if (child.pid && process.platform !== 'win32') process.kill(-child.pid, 'SIGKILL');
        else child.kill('SIGKILL');
      } catch {
        /* already gone */
      }
    };
    const timer = opts.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          killTree();
        }, opts.timeoutMs)
      : undefined;
    child.on('error', (e) => {
      if (timer) clearTimeout(timer);
      reject(e);
    });
    child.on('close', (code, signal) => {
      if (timer) clearTimeout(timer);
      resolve({
        code,
        signal,
        stdout: Buffer.concat(out),
        stderr: Buffer.concat(err),
        stdoutTruncated: outTrunc,
        stderrTruncated: errTrunc,
        timedOut,
      });
    });
    child.stdin.on('error', () => undefined); // EPIPE if child ignores stdin
    if (opts.stdin !== undefined) child.stdin.end(opts.stdin);
    else child.stdin.end();
  });
