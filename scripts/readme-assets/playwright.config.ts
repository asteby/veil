import { defineConfig } from '@playwright/test';

// Regenerates the README screenshots and the flow recording from the real local UI.
//   npx playwright test --config scripts/readme-assets/playwright.config.ts
// Output: docs/assets/shots/*.webp and docs/assets/flow-*.webp (needs ffmpeg with libwebp).
export default defineConfig({
  testDir: '.',
  testMatch: /capture\.spec\.ts$/,
  timeout: 120_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
});
