// Records everything a reader needs to judge whether two runs are comparable.
// Every field is read from the machine at run time; nothing is typed in.

import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Redis } from 'ioredis';

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(here, '../../../..');
const require = createRequire(path.join(here, '..', 'package.json'));

function sh(cmd) {
  try {
    return execSync(cmd, { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'ignore'], timeout: 15_000 }).toString().trim();
  } catch {
    return null;
  }
}

function pkgVersion(spec, from = require) {
  try { return from(`${spec}/package.json`).version; } catch { return null; }
}

function workspaceVersion(dir) {
  try { return createRequire(path.join(REPO_ROOT, dir, 'package.json'))(path.join(REPO_ROOT, dir, 'package.json')).version; } catch { return null; }
}

export async function captureEnvironment(redisUrl) {
  const redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 });
  let redisInfo = null;
  try {
    await redis.connect();
    const info = await redis.info('server');
    const pick = (k) => (info.match(new RegExp(`^${k}:(.*)$`, 'm')) ?? [])[1]?.trim() ?? null;
    const config = {};
    for (const key of ['save', 'appendonly', 'maxmemory', 'maxmemory-policy', 'io-threads', 'hz']) {
      const [, value] = await redis.config('GET', key);
      config[key] = value ?? null;
    }
    redisInfo = {
      url: redisUrl.replace(/\/\/[^@]*@/, '//***@'),
      version: pick('redis_version'),
      mode: pick('redis_mode'),
      os: pick('os'),
      archBits: pick('arch_bits'),
      config,
    };
  } catch (error) {
    redisInfo = { url: redisUrl, error: String(error) };
  } finally {
    redis.disconnect();
  }

  const cpus = os.cpus();
  return {
    capturedAt: new Date().toISOString(),
    git: {
      commit: sh('git rev-parse HEAD'),
      branch: sh('git rev-parse --abbrev-ref HEAD'),
      // Uncommitted changes are listed, not hidden: a number measured on a
      // dirty tree is a measurement of that tree.
      dirty: (sh('git status --porcelain') ?? '').split('\n').filter(Boolean),
    },
    runtime: {
      node: process.version,
      npm: sh('npm -v'),
      v8: process.versions.v8,
      openssl: process.versions.openssl,
      execArgv: process.execArgv,
      NODE_ENV: process.env.NODE_ENV ?? null,
    },
    os: {
      platform: process.platform,
      release: os.release(),
      version: typeof os.version === 'function' ? os.version() : null,
      arch: process.arch,
      powerPlan: process.platform === 'win32' ? sh('powercfg /getactivescheme') : null,
    },
    cpu: {
      model: cpus[0]?.model ?? null,
      logicalCores: cpus.length,
      physicalCores: process.platform === 'win32'
        ? Number(sh('powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).NumberOfCores"')) || null
        : null,
      speedMHz: cpus[0]?.speed ?? null,
    },
    memory: { totalBytes: os.totalmem(), freeBytesAtStart: os.freemem() },
    redis: redisInfo,
    docker: {
      server: sh('docker version --format "{{.Server.Version}}"'),
      runningContainers: (sh('docker ps --format "{{.Image}} {{.Names}}"') ?? '').split('\n').filter(Boolean),
    },
    packages: {
      '@ninshorg/core': workspaceVersion('packages/core'),
      '@ninshorg/server': workspaceVersion('packages/server'),
      express: pkgVersion('express'),
      ioredis: pkgVersion('ioredis'),
      jose: pkgVersion('jose'),
    },
  };
}
