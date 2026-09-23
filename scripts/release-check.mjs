#!/usr/bin/env node
/**
 * Pre-publish check. Verifies a release is ready; never publishes one.
 *
 *   npm run build && npm run release:check
 *
 * ─── Why it checks and stops ──────────────────────────────────────────────
 * Publishing is deliberately manual. Nothing in this repository is wired to
 * push to npm — no release workflow, no semantic-release, no token in CI —
 * and that is a maintainer decision, not an omission. Every release is a
 * person typing `npm publish` on purpose.
 *
 * What that decision gives up is the machine's memory for the fiddly parts,
 * and the first publish needed four attempts to learn them: 2FA, then
 * `--access public`, then an organisation matching the scope, then the right
 * organisation. This script is that memory. It runs every check a release
 * needs, and if they all pass it prints the exact commands, in dependency
 * order, for a person to run.
 * ──────────────────────────────────────────────────────────────────────────
 */
import { execSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
/** Publish order: `core` first, because `server` and `webauthn` pin it. */
const PUBLISHABLE = ['core', 'client', 'webauthn', 'server'];

const read = (path) => JSON.parse(readFileSync(join(ROOT, path), 'utf8'));

/**
 * `shell: true` because npm is `npm.cmd` on Windows, and Node refuses to spawn
 * a .cmd without a shell. Every command here is a fixed string built from this
 * repository's own package names — no outside input reaches it.
 */
function run(command) {
  return execSync(command, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], shell: true }).trim();
}

const results = [];
const pass = (label, detail = '') => results.push({ state: 'pass', label, detail });
const fail = (label, detail) => results.push({ state: 'fail', label, detail });
const warn = (label, detail) => results.push({ state: 'warn', label, detail });

// ── 1. One version for every package ───────────────────────────────────────
const manifests = Object.fromEntries(PUBLISHABLE.map((p) => [p, read(`packages/${p}/package.json`)]));
const versions = new Set(Object.values(manifests).map((m) => m.version));
const VERSION = [...versions][0];
if (versions.size === 1) {
  pass('Packages share one version', VERSION);
} else {
  fail(
    'Packages share one version',
    `found ${[...versions].join(', ')}. The four packages release in lockstep — see docs/stability.md.`,
  );
}

// ── 2. Internal dependencies pin that version exactly ──────────────────────
const workspaces = [
  ...PUBLISHABLE.map((p) => `packages/${p}`),
  ...readdirSync(join(ROOT, 'examples')).map((e) => `examples/${e}`),
].filter((dir) => existsSync(join(ROOT, dir, 'package.json')));

const stalePins = [];
for (const dir of workspaces) {
  const m = read(`${dir}/package.json`);
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies']) {
    for (const [dep, range] of Object.entries(m[field] ?? {})) {
      if (dep.startsWith('@ninshorg/') && range !== VERSION) stalePins.push(`${dir}: ${dep}@${range}`);
    }
  }
}
if (stalePins.length === 0) {
  pass('Internal dependencies pin the release version');
} else {
  // A server that pins an older core would install two copies of core, and an
  // error thrown by one would fail `instanceof` against the other's class.
  fail('Internal dependencies pin the release version', stalePins.join('; '));
}

// ── 3. Scoped packages publish publicly ────────────────────────────────────
const privateByDefault = PUBLISHABLE.filter((p) => manifests[p].publishConfig?.access !== 'public');
if (privateByDefault.length === 0) {
  pass('publishConfig.access is "public" everywhere');
} else {
  // The 402 the first publish hit: a scoped package defaults to private.
  fail('publishConfig.access is "public" everywhere', `missing on ${privateByDefault.join(', ')}`);
}

// ── 4. One supported runtime floor ─────────────────────────────────────────
const floors = new Set([read('package.json').engines?.node, ...PUBLISHABLE.map((p) => manifests[p].engines?.node)]);
if (floors.size === 1) pass('engines.node agrees across the workspace', [...floors][0]);
else fail('engines.node agrees across the workspace', `found ${[...floors].join(', ')}`);

// ── 5. The changelog says what shipped, and when ───────────────────────────
const changelog = readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf8');
const heading = changelog.split('\n').find((line) => line.startsWith(`## [${VERSION}]`));
if (!heading) {
  fail('CHANGELOG has an entry for this version', `no "## [${VERSION}]" heading`);
} else if (/unreleased/i.test(heading)) {
  fail(
    'CHANGELOG entry is dated',
    `"${heading.trim()}" — replace "Unreleased" with today's date as the last step before publishing`,
  );
} else {
  pass('CHANGELOG entry is dated', heading.replace(/^##\s*/, ''));
}

// ── 6. Built, and the public API is the one on record ──────────────────────
const missingDist = [];
for (const p of PUBLISHABLE) {
  for (const target of Object.values(manifests[p].exports)) {
    for (const file of [target?.import?.default, target?.require?.default, target?.import?.types]) {
      if (typeof file === 'string' && !existsSync(join(ROOT, 'packages', p, file))) missingDist.push(`${p}/${file}`);
    }
  }
}
if (missingDist.length > 0) {
  fail('Every export resolves to a built file', `run \`npm run build\` — missing ${missingDist.slice(0, 4).join(', ')}`);
} else {
  pass('Every export resolves to a built file');
  try {
    run('node scripts/api-report.mjs --check');
    pass('Public API matches api/*.api.md');
  } catch (error) {
    fail('Public API matches api/*.api.md', (error.stderr || error.message).split('\n').slice(0, 3).join(' '));
  }
}

// ── 7. The tarballs hold what they should and nothing else ─────────────────
const ALLOWED = [/^package\.json$/, /^README\.md$/, /^LICENSE$/, /^dist\//];
for (const p of PUBLISHABLE) {
  try {
    const [report] = JSON.parse(run(`npm pack --dry-run --json --workspace @ninshorg/${p}`));
    const stray = report.files.map((f) => f.path).filter((path) => !ALLOWED.some((re) => re.test(path)));
    const tests = report.files.map((f) => f.path).filter((path) => /\.test\.|__tests__|fixtures?\//.test(path));
    if (stray.length === 0 && tests.length === 0) {
      pass(`@ninshorg/${p} tarball contents`, `${report.files.length} files, ${(report.size / 1024).toFixed(1)} KB packed`);
    } else {
      fail(`@ninshorg/${p} tarball contents`, `unexpected: ${[...stray, ...tests].slice(0, 5).join(', ')}`);
    }
  } catch (error) {
    fail(`@ninshorg/${p} tarball contents`, `npm pack failed: ${error.message.split('\n')[0]}`);
  }
}

// ── 8. Not already on the registry ─────────────────────────────────────────
for (const p of PUBLISHABLE) {
  try {
    const published = run(`npm view @ninshorg/${p}@${VERSION} version`);
    if (published === VERSION) {
      fail(`@ninshorg/${p}@${VERSION} is unpublished`, 'already on npm — a published version can never be replaced; bump it');
    } else {
      pass(`@ninshorg/${p}@${VERSION} is unpublished`);
    }
  } catch (error) {
    const text = `${error.stdout ?? ''}${error.stderr ?? ''}`;
    if (/E404|not found|No match found/i.test(text)) pass(`@ninshorg/${p}@${VERSION} is unpublished`);
    else warn(`@ninshorg/${p}@${VERSION} is unpublished`, 'could not reach the registry to confirm');
  }
}

// ── 9. Publishing from a known commit ──────────────────────────────────────
try {
  const dirty = run('git status --porcelain --untracked-files=no');
  if (dirty) fail('Working tree is clean', `uncommitted changes:\n      ${dirty.split('\n').slice(0, 5).join('\n      ')}`);
  else pass('Working tree is clean');

  const branch = run('git rev-parse --abbrev-ref HEAD');
  if (branch === 'main') pass('On main');
  else warn('On main', `on "${branch}" — releases are cut from main once this branch is merged`);

  run('git fetch --quiet origin main');
  const behind = Number(run('git rev-list --count HEAD..origin/main'));
  if (behind > 0) fail('Up to date with origin/main', `${behind} commit(s) behind`);
  else pass('Up to date with origin/main');

  const sha = run('git rev-parse HEAD');
  try {
    const runs = JSON.parse(run(`gh run list --commit ${sha} --workflow CI --json status,conclusion`));
    if (runs.length === 0) warn('CI is green on this commit', 'no CI run found for HEAD — push it and wait for one');
    else if (runs.some((r) => r.conclusion === 'success')) pass('CI is green on this commit', sha.slice(0, 7));
    else if (runs.some((r) => r.status !== 'completed')) warn('CI is green on this commit', 'still running');
    else fail('CI is green on this commit', `latest conclusion: ${runs[0].conclusion}`);
  } catch {
    warn('CI is green on this commit', 'gh CLI unavailable — check the Actions tab by hand');
  }
} catch (error) {
  warn('Git state', error.message.split('\n')[0]);
}

// ── Report ─────────────────────────────────────────────────────────────────
const icon = { pass: '✓', fail: '✗', warn: '!' };
console.log(`\nRelease check — v${VERSION}\n`);
for (const r of results) {
  console.log(`  ${icon[r.state]} ${r.label}${r.detail ? `\n      ${r.detail}` : ''}`);
}

const failures = results.filter((r) => r.state === 'fail').length;
const warnings = results.filter((r) => r.state === 'warn').length;

if (failures > 0) {
  console.log(`\n${failures} check(s) failed. Nothing to publish yet.\n`);
  process.exit(1);
}

console.log(`\nReady${warnings ? ` (${warnings} warning(s) above — read them)` : ''}. To publish, run these yourself:\n`);
for (const p of PUBLISHABLE) console.log(`  npm publish --workspace @ninshorg/${p} --otp=<code>`);
console.log(
  `\nThen tag it:  git tag v${VERSION} && git push origin v${VERSION}` +
    '\nAnd confirm from the registry, not from the upload: install all four in a' +
    '\nscratch project and create a session — npm view only proves the upload.\n',
);
