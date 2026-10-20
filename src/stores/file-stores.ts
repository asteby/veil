import type { FileIO, WriteOpts } from '../fileio.js';
import { deleteEnvKey, getEnvKey, setEnvKey } from '../fileformats.js';
import { ENV_KEY_RE, KeyedMutex, UserError } from '../util.js';
import type { PutResult, SecretStore } from './types.js';

const mutex = new KeyedMutex();

/** Plain .env file (local or remote over SSH), 0600, atomic replace, preserves the rest of the file. */
export class EnvFileStore implements SecretStore {
  readonly type = 'env-file';
  readonly readable = true;

  constructor(
    readonly id: string,
    private readonly io: FileIO,
    private readonly path: string,
    private readonly opts: WriteOpts,
  ) {}

  put(name: string, value: string): Promise<PutResult> {
    if (!ENV_KEY_RE.test(name)) throw new UserError(`"${name}" is not a valid env key for ${this.id}`, 'invalid_key');
    return mutex.run(`${this.io.where}:${this.path}`, async () => {
      const cur = (await this.io.read(this.path))?.toString('utf8') ?? '';
      const { content, action } = setEnvKey(cur, name, value);
      await this.io.writeAtomic(this.path, content, this.opts);
      return { action };
    });
  }

  async get(name: string): Promise<string | undefined> {
    const cur = await this.io.read(this.path);
    return cur ? getEnvKey(cur.toString('utf8'), name) : undefined;
  }

  delete(name: string): Promise<boolean> {
    return mutex.run(`${this.io.where}:${this.path}`, async () => {
      const cur = await this.io.read(this.path);
      if (!cur) return false;
      const { content, removed } = deleteEnvKey(cur.toString('utf8'), name);
      if (removed) await this.io.writeAtomic(this.path, content, this.opts);
      return removed;
    });
  }

  describe(): string {
    return `env file ${this.path} (${this.io.where})`;
  }
}

/**
 * One remote file per secret over SSH (`path` may contain {name}). Write-only: the
 * value is a deployment artefact; the MCP never reads it back.
 */
export class SshFileStore implements SecretStore {
  readonly type = 'ssh-file';
  readonly readable = false;

  constructor(
    readonly id: string,
    private readonly io: FileIO,
    private readonly pathTemplate: string,
    private readonly opts: WriteOpts,
  ) {}

  private pathFor(name: string): string {
    return this.pathTemplate.includes('{name}') ? this.pathTemplate.split('{name}').join(name) : this.pathTemplate;
  }

  async put(name: string, value: string): Promise<PutResult> {
    const p = this.pathFor(name);
    const existed = (await this.io.read(p)) !== null;
    await this.io.writeAtomic(p, value, this.opts);
    return { action: existed ? 'updated' : 'created' };
  }

  async get(): Promise<string | undefined> {
    throw new UserError(`destination ${this.id} is write-only (ssh-file)`, 'not_readable');
  }

  delete(name: string): Promise<boolean> {
    return this.io.remove(this.pathFor(name));
  }

  describe(): string {
    return `remote file ${this.pathTemplate} (${this.io.where}, mode ${this.opts.mode ?? '0600'}${this.opts.owner ? `, owner ${this.opts.owner}` : ''}${this.opts.group ? `:${this.opts.group}` : ''})`;
  }
}
