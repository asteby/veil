export interface PutResult {
  action: 'created' | 'updated';
}

/**
 * A place where secret values live. Implementations MUST NOT log values and MUST
 * NOT include values in thrown error messages.
 */
export interface SecretStore {
  readonly id: string;
  readonly type: string;
  /** false for write-only deployment targets such as ssh-file. */
  readonly readable: boolean;
  put(name: string, value: string): Promise<PutResult>;
  get(name: string): Promise<string | undefined>;
  delete(name: string): Promise<boolean>;
  /** Human-readable, non-secret description of where values go (shown on approval/form pages). */
  describe(): string;
}

/** Resolves a reference to a value held in a LOCAL store (used for bootstrap tokens). */
export type LocalResolver = (ref: string) => Promise<string>;
