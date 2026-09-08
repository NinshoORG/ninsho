import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'src/fastify.ts', 'src/hono.ts', 'src/koa.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'node20',
  outDir: 'dist',
  splitting: false,
  treeshake: true,
  // Everything with a runtime cost stays external. The predecessor bundled a
  // dev-only Redis mock into its published artifact because it was absent from
  // this list; CI now also greps dist/ to make that impossible to repeat.
  external: ['ioredis', '@ninshorg/core'],
});
