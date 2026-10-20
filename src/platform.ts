/**
 * Platform facts used by `veilform doctor`, `veilform init` and the actionable error
 * catalog: OS, Linux distribution, package manager and the EXACT install command for a
 * missing tool. Detection only reads files and scans PATH; it never runs anything
 * privileged (and never runs a package manager).
 */
import { accessSync, constants, existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

export type PackageManager = 'apt' | 'dnf' | 'pacman' | 'zypper' | 'apk' | 'brew' | 'winget' | 'unknown';

export interface PlatformInfo {
  os: NodeJS.Platform;
  /** os-release ID (linuxmint, ubuntu, fedora, arch...) or 'macos' / 'windows' */
  distro: string;
  distroName?: string;
  idLike: string[];
  packageManager: PackageManager;
}

/** Abstract tools Veil may need; mapped to a package per package manager. */
export type Tool = 'secret-tool' | 'gnome-keyring' | 'dbus-user-session' | 'ssh' | 'git' | 'gh' | 'psql' | 'chromium' | 'xdg-open' | 'node';

const PACKAGES: Record<Tool, Partial<Record<PackageManager, string>>> = {
  'secret-tool': { apt: 'libsecret-tools', dnf: 'libsecret', pacman: 'libsecret', zypper: 'libsecret-tools', apk: 'libsecret' },
  'gnome-keyring': { apt: 'gnome-keyring', dnf: 'gnome-keyring', pacman: 'gnome-keyring', zypper: 'gnome-keyring', apk: 'gnome-keyring' },
  'dbus-user-session': { apt: 'dbus-user-session', dnf: 'dbus-daemon', pacman: 'dbus', zypper: 'dbus-1', apk: 'dbus' },
  ssh: { apt: 'openssh-client', dnf: 'openssh-clients', pacman: 'openssh', zypper: 'openssh-clients', apk: 'openssh-client', brew: 'openssh', winget: 'Microsoft.OpenSSH.Beta' },
  git: { apt: 'git', dnf: 'git', pacman: 'git', zypper: 'git', apk: 'git', brew: 'git', winget: 'Git.Git' },
  gh: { apt: 'gh', dnf: 'gh', pacman: 'github-cli', zypper: 'gh', apk: 'github-cli', brew: 'gh', winget: 'GitHub.cli' },
  psql: { apt: 'postgresql-client', dnf: 'postgresql', pacman: 'postgresql', zypper: 'postgresql', apk: 'postgresql-client', brew: 'libpq', winget: 'PostgreSQL.PostgreSQL' },
  chromium: { apt: 'chromium', dnf: 'chromium', pacman: 'chromium', zypper: 'chromium', apk: 'chromium', brew: '--cask chromium', winget: 'Hibbiki.Chromium' },
  'xdg-open': { apt: 'xdg-utils', dnf: 'xdg-utils', pacman: 'xdg-utils', zypper: 'xdg-utils', apk: 'xdg-utils' },
  node: { apt: 'nodejs', dnf: 'nodejs', pacman: 'nodejs', zypper: 'nodejs', apk: 'nodejs', brew: 'node', winget: 'OpenJS.NodeJS' },
};

const FAMILY: { pm: PackageManager; ids: string[] }[] = [
  { pm: 'apt', ids: ['debian', 'ubuntu', 'linuxmint', 'pop', 'elementary', 'zorin', 'kali', 'raspbian', 'neon', 'deepin', 'mx'] },
  { pm: 'dnf', ids: ['fedora', 'rhel', 'centos', 'rocky', 'almalinux', 'ol', 'nobara', 'amzn'] },
  { pm: 'pacman', ids: ['arch', 'manjaro', 'endeavouros', 'garuda', 'artix', 'cachyos'] },
  { pm: 'zypper', ids: ['opensuse', 'opensuse-leap', 'opensuse-tumbleweed', 'sles', 'suse'] },
  { pm: 'apk', ids: ['alpine'] },
];

/** Parses /etc/os-release content (KEY=value, optional quotes). */
export function parseOsRelease(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (!m) continue;
    out[m[1]!] = m[2]!.replace(/^"(.*)"$/, '$1').replace(/^'(.*)'$/, '$1');
  }
  return out;
}

export function detectPlatform(opts: { platform?: NodeJS.Platform; osRelease?: string } = {}): PlatformInfo {
  const os = opts.platform ?? process.platform;
  if (os === 'darwin') return { os, distro: 'macos', idLike: [], packageManager: 'brew' };
  if (os === 'win32') return { os, distro: 'windows', idLike: [], packageManager: 'winget' };
  let text = opts.osRelease;
  if (text === undefined) {
    for (const f of ['/etc/os-release', '/usr/lib/os-release']) {
      try {
        text = readFileSync(f, 'utf8');
        break;
      } catch {
        /* next */
      }
    }
  }
  const rel = parseOsRelease(text ?? '');
  const id = (rel.ID ?? 'linux').toLowerCase();
  const idLike = (rel.ID_LIKE ?? '').toLowerCase().split(/\s+/).filter(Boolean);
  let pm: PackageManager = 'unknown';
  for (const cand of [id, ...idLike]) {
    const fam = FAMILY.find((f) => f.ids.includes(cand) || (cand.startsWith('opensuse') && f.pm === 'zypper'));
    if (fam) {
      pm = fam.pm;
      break;
    }
  }
  return { os, distro: id, distroName: rel.PRETTY_NAME ?? rel.NAME, idLike, packageManager: pm };
}

/** Exact command a PERSON copies to install `tool`. Veil never runs it (it needs sudo). */
export function installCommand(tool: Tool, p: PlatformInfo): string | undefined {
  if (tool === 'chromium') return 'npx playwright install chromium';
  const pkg = PACKAGES[tool][p.packageManager];
  if (!pkg) return undefined;
  switch (p.packageManager) {
    case 'apt':
      return `sudo apt install -y ${pkg}`;
    case 'dnf':
      return `sudo dnf install -y ${pkg}`;
    case 'pacman':
      return `sudo pacman -S --needed ${pkg}`;
    case 'zypper':
      return `sudo zypper install -y ${pkg}`;
    case 'apk':
      return `sudo apk add ${pkg}`;
    case 'brew':
      return `brew install ${pkg}`;
    case 'winget':
      return `winget install --id ${pkg}`;
    default:
      return undefined;
  }
}

/** Finds an executable in PATH without spawning anything. */
export function which(cmd: string, env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string | undefined {
  if (cmd.includes('/') || cmd.includes('\\')) return isExecutable(cmd) ? cmd : undefined;
  const exts = platform === 'win32' ? (env.PATHEXT ?? '.EXE;.CMD;.BAT').split(';') : [''];
  for (const dir of (env.PATH ?? '').split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const f = path.join(dir, cmd + ext);
      if (isExecutable(f)) return f;
    }
  }
  return undefined;
}

function isExecutable(f: string): boolean {
  try {
    if (!existsSync(f)) return false;
    accessSync(f, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

let cached: PlatformInfo | undefined;
/** Cached detection for the current machine (used by the error catalog). */
export function currentPlatform(): PlatformInfo {
  return (cached ??= detectPlatform());
}
