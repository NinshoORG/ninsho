import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
    testTimeout: 20_000,
    // The server module binds a port when imported directly; the tests listen
    // on an ephemeral one themselves.
    env: { PLAYGROUND_NO_LISTEN: '1' },
  },
});
