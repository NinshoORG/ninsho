import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  // Browser target: no Node built-ins are used, so nothing needs shimming.
  target: 'es2022',
  platform: 'neutral',
  outDir: 'dist',
  splitting: false,
  treeshake: true,
});
