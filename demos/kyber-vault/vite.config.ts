import { defineConfig } from 'vite';

function normalizeBasePath(basePath: string): string {
  const trimmed = basePath.trim();
  if (trimmed === '' || trimmed === '/') {
    return '/';
  }
  return `/${trimmed.replace(/^\/+|\/+$/g, '')}/`;
}

export default defineConfig(({ mode }) => {
  const configuredBase = process.env.VITE_BASE_PATH;
  const fallbackBase = mode === 'production' ? '/kyber-vault/' : '/';

  return {
    base: normalizeBasePath(configuredBase ?? fallbackBase),
  };
});
