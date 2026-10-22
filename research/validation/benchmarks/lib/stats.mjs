// Descriptive statistics shared by both comparisons.
//
// Percentiles use the nearest-rank method on the sorted sample, which is the
// definition most load tools report and has no interpolation to argue about.

export function percentile(sorted, p) {
  if (sorted.length === 0) return Number.NaN;
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(sorted.length, Math.max(1, rank)) - 1];
}

export function describe(samplesMs) {
  const sorted = Float64Array.from(samplesMs).sort();
  const n = sorted.length;
  let sum = 0;
  for (const v of sorted) sum += v;
  const mean = sum / n;
  let sq = 0;
  for (const v of sorted) sq += (v - mean) ** 2;
  return {
    n,
    meanMs: mean,
    stdevMs: n > 1 ? Math.sqrt(sq / (n - 1)) : 0,
    minMs: sorted[0],
    p50Ms: percentile(sorted, 50),
    p95Ms: percentile(sorted, 95),
    p99Ms: percentile(sorted, 99),
    maxMs: sorted[n - 1],
  };
}

/** Median and spread of one metric across independent trials. */
export function acrossTrials(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const n = sorted.length;
  const median = n % 2 === 1 ? sorted[(n - 1) / 2] : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;
  const mean = sorted.reduce((s, v) => s + v, 0) / n;
  const sd = n > 1 ? Math.sqrt(sorted.reduce((s, v) => s + (v - mean) ** 2, 0) / (n - 1)) : 0;
  return { median, min: sorted[0], max: sorted[n - 1], cvPercent: mean === 0 ? 0 : (sd / mean) * 100, n };
}

export function shuffle(items, seed) {
  // Deterministic order per trial, so a rerun interleaves configurations the
  // same way and the order is recorded rather than accidental.
  const out = [...items];
  let s = seed >>> 0;
  const next = () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 2 ** 32; };
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = Math.floor(next() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}
