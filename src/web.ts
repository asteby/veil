import { z } from 'zod';
import type { Config } from './config.js';
import { secretRefsDeep, SECRET_REF } from './templates.js';
import { globMatch, UserError } from './util.js';
import type { Vault } from './vault.js';

/**
 * Blind web actions in a browser owned by this MCP (Playwright, visible window by
 * default). The person logs in themselves; the model only declares steps and an
 * extractor. NOTHING from the page (text, DOM, HTML, screenshots, URLs with query
 * strings, Playwright error messages) is returned: only step indexes and codes.
 */
export const WebStep = z.union([
  z.object({ navigate: z.string() }),
  z.object({ click: z.string() }),
  z.object({ wait: z.string().describe('CSS/Playwright selector to wait for (e.g. after the person logs in)'), timeout_ms: z.number().int().positive().optional() }),
  z.object({ wait_for_url: z.string().describe('glob on origin+path, e.g. https://example.com/dashboard*'), timeout_ms: z.number().int().positive().optional() }),
  z.object({ fill: z.string(), value: z.string().describe('literal or ${secret:name}') }),
  z.object({ press: z.string(), selector: z.string().optional() }),
]);
export type WebStepT = z.infer<typeof WebStep>;

export const Extractor = z.object({
  selector: z.string(),
  attribute: z.string().optional().describe('read this attribute instead of the text'),
  property: z.enum(['textContent', 'innerText', 'value']).optional(),
  regex: z.string().max(500).optional().describe('optional regex; first capture group (or whole match) is kept'),
});
export type ExtractorT = z.infer<typeof Extractor>;

export interface WebRunResult {
  status: 'completed' | 'failed';
  steps_completed: number;
  failed_step?: number;
  error_code?: string;
  value?: string; // never returned to the model; consumed by the caller
}

interface SessionBlob {
  savedAt: number;
  state: unknown;
}

type PwPage = {
  goto(url: string, o?: object): Promise<unknown>;
  url(): string;
  click(sel: string, o?: object): Promise<void>;
  fill(sel: string, v: string, o?: object): Promise<void>;
  press(sel: string, key: string, o?: object): Promise<void>;
  keyboard: { press(key: string): Promise<void> };
  waitForSelector(sel: string, o?: object): Promise<unknown>;
  waitForURL(fn: (u: URL) => boolean, o?: object): Promise<void>;
  locator(sel: string): { first(): { getAttribute(a: string, o?: object): Promise<string | null>; textContent(o?: object): Promise<string | null>; innerText(o?: object): Promise<string>; inputValue(o?: object): Promise<string> } };
};

export function siteOf(cfg: Config, site: string) {
  const s = cfg.web.sites[site];
  if (!s) throw new UserError(`web site "${site}" is not in the web.sites allowlist`, 'site_not_allowed');
  return s;
}

function originAllowed(origins: string[], url: string): boolean {
  try {
    const o = new URL(url).origin;
    return origins.some((p) => globMatch(p, o));
  } catch {
    return false;
  }
}

/** Validates start URL and navigate steps against the site's origins (before asking for approval). */
export function checkWebPlan(cfg: Config, site: string, url: string, steps: WebStepT[]): void {
  const s = siteOf(cfg, site);
  if (!originAllowed(s.origins, url)) throw new UserError('start URL is outside the site origins allowlist', 'origin_not_allowed');
  for (const st of steps) if ('navigate' in st && !originAllowed(s.origins, st.navigate)) throw new UserError('navigate step is outside the site origins allowlist', 'origin_not_allowed');
}

/** Literal rendering of steps for the approval page. */
export function stepsLiteral(url: string, steps: WebStepT[], extract?: ExtractorT): string {
  const lines = [`open ${url}`];
  steps.forEach((s, i) => lines.push(`${i + 1}. ${JSON.stringify(s)}`));
  if (extract) lines.push(`extract ${JSON.stringify(extract)}`);
  return lines.join('\n');
}

export class WebRunner {
  constructor(
    private readonly cfg: Config,
    private readonly vault: Vault,
    private readonly loader: () => Promise<unknown> = () => import('playwright-core' as string),
  ) {}

  private sessionName(site: string): string {
    return `web_session.${site}`;
  }

  private async loadSession(site: string): Promise<unknown | undefined> {
    const meta = this.vault.meta(`${this.vault.internalDestination}:${this.sessionName(site)}`);
    if (!meta) return undefined;
    try {
      const blob = JSON.parse((await this.vault.resolve(`${this.vault.internalDestination}:${this.sessionName(site)}`)).value) as SessionBlob;
      if (Date.now() - blob.savedAt > this.cfg.web.sessionTtlHours * 3_600_000) return undefined;
      return blob.state;
    } catch {
      return undefined;
    }
  }

  async run(site: string, url: string, steps: WebStepT[], extract: ExtractorT | undefined, opts: { saveSession: boolean }): Promise<WebRunResult> {
    const s = siteOf(this.cfg, site);
    checkWebPlan(this.cfg, site, url, steps);
    const refs = secretRefsDeep(steps);
    const secrets = new Map<string, string>();
    for (const r of refs) secrets.set(r, (await this.vault.resolve(r)).value);

    let pw: { chromium: { launch(o: object): Promise<{ newContext(o: object): Promise<{ newPage(): Promise<PwPage>; storageState(): Promise<unknown>; close(): Promise<void> }>; close(): Promise<void> }> } };
    try {
      pw = (await this.loader()) as typeof pw;
    } catch {
      throw new UserError('playwright-core is not installed: npm i -g playwright-core && npx playwright-core install chromium', 'playwright_missing');
    }
    const browser = await pw.chromium.launch({ headless: this.cfg.web.headless, executablePath: this.cfg.web.executablePath });
    let done = 0;
    try {
      const storageState = await this.loadSession(site);
      const ctx = await browser.newContext({ storageState, acceptDownloads: false, serviceWorkers: 'block' });
      const page = await ctx.newPage();
      const timeout = this.cfg.web.stepTimeoutMs;
      const guard = () => {
        if (!originAllowed(s.origins, page.url())) throw new UserError('page left the allowed origins', 'origin_not_allowed');
      };
      try {
        await page.goto(url, { timeout });
        for (const st of steps) {
          if ('navigate' in st) await page.goto(st.navigate, { timeout });
          else if ('click' in st) {
            guard();
            await page.click(st.click, { timeout });
          } else if ('wait' in st) await page.waitForSelector(st.wait, { timeout: st.timeout_ms ?? timeout, state: 'attached' });
          else if ('wait_for_url' in st) await page.waitForURL((u) => globMatch(st.wait_for_url, u.origin + u.pathname), { timeout: st.timeout_ms ?? timeout });
          else if ('fill' in st) {
            guard(); // secrets are only typed into allowlisted origins
            const v = st.value.replace(SECRET_REF, (_m, ref: string) => secrets.get(ref) ?? '');
            await page.fill(st.fill, v, { timeout });
          } else if ('press' in st) {
            if (st.selector) await page.press(st.selector, st.press, { timeout });
            else await page.keyboard.press(st.press);
          }
          done++;
        }
        let value: string | undefined;
        if (extract) {
          guard();
          const loc = page.locator(extract.selector).first();
          let raw: string | null;
          if (extract.attribute) raw = await loc.getAttribute(extract.attribute, { timeout });
          else if (extract.property === 'value') raw = await loc.inputValue({ timeout });
          else if (extract.property === 'innerText') raw = await loc.innerText({ timeout });
          else raw = await loc.textContent({ timeout });
          raw = (raw ?? '').trim();
          if (extract.regex) {
            const m = new RegExp(extract.regex, 'u').exec(raw);
            raw = m ? (m[1] ?? m[0]) : '';
          }
          if (!raw) return { status: 'failed', steps_completed: done, failed_step: steps.length + 1, error_code: 'extract_empty' };
          value = raw;
        }
        if (opts.saveSession) {
          const state = await ctx.storageState();
          await this.vault.put(this.vault.internalDestination, this.sessionName(site), JSON.stringify({ savedAt: Date.now(), state } satisfies SessionBlob), { tags: ['web-session'], source: 'web' });
        }
        await ctx.close();
        return { status: 'completed', steps_completed: done, value };
      } catch (e) {
        // Map to a code; never surface Playwright's message (it can contain page text).
        const code = e instanceof UserError ? e.code : (e as Error)?.name === 'TimeoutError' ? 'timeout' : 'step_failed';
        return { status: 'failed', steps_completed: done, failed_step: done + 1, error_code: code };
      }
    } finally {
      await browser.close().catch(() => undefined);
    }
  }
}
