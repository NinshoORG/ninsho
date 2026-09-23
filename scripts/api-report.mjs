#!/usr/bin/env node
/**
 * The public API, written down.
 *
 *   npm run api:report   regenerate api/*.api.md from the built declarations
 *   npm run api:check    fail if the built declarations no longer match them
 *
 * ─── Why this exists ──────────────────────────────────────────────────────
 * docs/stability.md promises that a minor release does not break what a
 * consumer compiles against. A promise like that is only as good as the
 * mechanism that notices when it is about to be broken, and without one the
 * honest description of it is "we will try to remember".
 *
 * So the surface is recorded. Each package's report is its declaration files,
 * exactly as a consumer's compiler reads them, one section per `exports`
 * entry. A pull request that changes the API changes a report, a reviewer
 * sees it, and CI refuses a change that forgot to regenerate — which is the
 * difference between an API change that was decided and one that happened.
 *
 * ─── What is normalised, and why only that ────────────────────────────────
 * tsup splits declarations shared between entry points into chunks named by
 * content hash (`types-hBzRYiTh.d.ts`). Left alone, any change inside a chunk
 * would also rewrite the import line of every entry that uses it, and the
 * diff a reviewer sees would be mostly hash churn. Chunk names lose their hash
 * here and nothing else is touched: no reformatting, no reordering, no
 * filtering. A report that editorialised the surface would be one more claim
 * that could drift from the thing it describes.
 * ──────────────────────────────────────────────────────────────────────────
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { dirname, join, resolve, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_DIR = join(ROOT, 'api');
const PACKAGES = ['core', 'server', 'client', 'webauthn'];

const check = process.argv.includes('--check');

/** LF only, no trailing whitespace, exactly one final newline. */
function tidy(text) {
  return (
    text
      .replace(/\r\n/g, '\n')
      .split('\n')
      .map((line) => line.replace(/\s+$/, ''))
      .join('\n')
      .replace(/\n+$/, '') + '\n'
  );
}

/**
 * Real chunk file stem → stable name. Built from the files actually on disk
 * rather than a pattern guessed at, so an entry point that happens to contain
 * a hyphen is never mistaken for a chunk.
 */
function chunkNames(distDir, entryStems) {
  const map = new Map();
  for (const file of readdirSync(distDir)) {
    if (!file.endsWith('.d.ts')) continue;
    const stem = file.slice(0, -'.d.ts'.length);
    if (entryStems.has(stem)) continue;
    const hashed = /^(.+)-[A-Za-z0-9_-]{8}$/.exec(stem);
    if (hashed) map.set(stem, hashed[1]);
  }
  return map;
}

function normalise(text, chunks) {
  let out = text;
  for (const [real, stable] of chunks) out = out.split(real).join(stable);
  // A source map comment names a file that is not part of the API.
  out = out.replace(/^\/\/# sourceMappingURL=.*$/gm, '');
  return tidy(out);
}

function reportFor(name) {
  const pkgDir = join(ROOT, 'packages', name);
  const manifest = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
  const distDir = join(pkgDir, 'dist');

  // Entry points in the order the manifest declares them, which is the order a
  // reader of package.json meets them in.
  const entries = Object.entries(manifest.exports).map(([subpath, target]) => {
    const types = target?.import?.types ?? target?.types;
    if (typeof types !== 'string') {
      throw new Error(`${manifest.name}: exports["${subpath}"] has no types condition`);
    }
    return {
      specifier: subpath === '.' ? manifest.name : posix.join(manifest.name, subpath),
      file: join(pkgDir, types),
    };
  });

  for (const entry of entries) {
    if (!existsSync(entry.file)) {
      throw new Error(
        `${entry.file} does not exist. Run \`npm run build\` first — the report is ` +
          'generated from built declarations, because those are what a consumer compiles against.',
      );
    }
  }

  const entryStems = new Set(
    entries.map((e) => e.file.replace(/\\/g, '/').split('/').pop().slice(0, -'.d.ts'.length)),
  );
  const chunks = chunkNames(distDir, entryStems);

  const sections = entries.map(({ specifier, file }) => [
    `## \`${specifier}\``,
    '',
    '```ts',
    normalise(readFileSync(file, 'utf8'), chunks).trimEnd(),
    '```',
  ]);

  // Shared chunks, sorted by their stable name so the order does not depend on
  // what the hash happened to be.
  const shared = [...chunks.entries()]
    .sort((a, b) => a[1].localeCompare(b[1]))
    .map(([real, stable]) => [
      `## Shared declarations: \`${stable}\``,
      '',
      'Referenced by the entry points above as `./' + stable + '.js`.',
      '',
      '```ts',
      normalise(readFileSync(join(distDir, `${real}.d.ts`), 'utf8'), chunks).trimEnd(),
      '```',
    ]);

  return tidy(
    [
      `# \`${manifest.name}\` — public API`,
      '',
      '<!--',
      '  Generated by scripts/api-report.mjs from the built declaration files.',
      '  Do not edit by hand: run `npm run build && npm run api:report`.',
      '-->',
      '',
      'This file is what a consumer\'s compiler sees when it imports this package.',
      'A change here is a change to the public API. Under',
      '[docs/stability.md](../docs/stability.md) a removal, a rename, or a',
      'signature that accepts less or returns more is a **breaking change**, and',
      'must not ship in a minor release.',
      '',
      ...sections.flatMap((s) => [...s, '']),
      ...shared.flatMap((s) => [...s, '']),
    ].join('\n'),
  );
}

/** First differing line, with a little context, so CI output is actionable. */
function firstDifference(expected, actual) {
  const a = expected.split('\n');
  const b = actual.split('\n');
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    if (a[i] !== b[i]) {
      return `line ${i + 1}:\n    recorded: ${JSON.stringify(a[i] ?? '<end of file>')}\n    built:    ${JSON.stringify(b[i] ?? '<end of file>')}`;
    }
  }
  return 'no line differs (whitespace only)';
}

let failed = false;
if (!check) mkdirSync(OUT_DIR, { recursive: true });

for (const name of PACKAGES) {
  const target = join(OUT_DIR, `${name}.api.md`);
  let built;
  try {
    built = reportFor(name);
  } catch (error) {
    console.error(`✗ ${name}: ${error.message}`);
    failed = true;
    continue;
  }

  if (!check) {
    writeFileSync(target, built);
    console.log(`  wrote api/${name}.api.md (${built.split('\n').length} lines)`);
    continue;
  }

  const recorded = existsSync(target) ? tidy(readFileSync(target, 'utf8')) : null;
  if (recorded === null) {
    console.error(`✗ api/${name}.api.md is missing. Run \`npm run api:report\` and commit it.`);
    failed = true;
  } else if (recorded !== built) {
    console.error(`✗ @ninshorg/${name}: the public API differs from api/${name}.api.md`);
    console.error(`  ${firstDifference(recorded, built)}`);
    failed = true;
  } else {
    console.log(`✓ @ninshorg/${name}: public API matches the recorded report`);
  }
}

if (failed && check) {
  console.error(
    '\nThe public API changed. If that was intended, run `npm run api:report`, commit\n' +
      'the result, and say in the pull request why — and whether it is breaking under\n' +
      'docs/stability.md. If it was not intended, this is the gate doing its job.',
  );
}
process.exit(failed ? 1 : 0);
