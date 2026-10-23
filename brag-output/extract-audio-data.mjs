/**
 * Extract per-frame audio band data for the Hyperframes audio-reactive layer.
 *
 * The hyperframes-creative skill ships a Python extractor (librosa). Python with
 * librosa is not available on this machine, so this does the same job with the
 * ffmpeg binary already installed locally: decode to mono PCM, split into three
 * bands with one-pole IIR filters, take per-frame RMS, normalise each band
 * independently across the window.
 *
 * Output matches the documented AUDIO_DATA shape:
 *   { fps, totalFrames, frames: [{ bands: [bass, mid, treble] }, ...] }
 *
 * Deterministic: no clocks, no randomness. Same input file -> same output.
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

// usage: node extract-audio-data.mjs [projectDir] [seconds]
const PROJECT = process.argv[2] || 'composition';
const SRC = resolve(`${PROJECT}/assets/music/bed.mp3`);
const OUT = resolve(`${PROJECT}/assets/music/bed.audio-data.json`);
const FFMPEG = resolve('.bin/ffmpeg.exe');

const FPS = 30;
const SECONDS = Number(process.argv[3] || 24); // one second past the composition
const RATE = 22050;

// Decode to mono 16-bit PCM at a known rate.
const raw = execFileSync(
  FFMPEG,
  ['-v', 'error', '-i', SRC, '-t', String(SECONDS), '-ac', '1', '-ar', String(RATE), '-f', 's16le', '-'],
  { maxBuffer: 1 << 28 },
);

const n = Math.floor(raw.length / 2);
const pcm = new Float32Array(n);
for (let i = 0; i < n; i += 1) pcm[i] = raw.readInt16LE(i * 2) / 32768;

/** One-pole lowpass. alpha derived from cutoff, so the filter is reproducible. */
function lowpass(signal, cutoffHz) {
  const dt = 1 / RATE;
  const rc = 1 / (2 * Math.PI * cutoffHz);
  const alpha = dt / (rc + dt);
  const out = new Float32Array(signal.length);
  let prev = 0;
  for (let i = 0; i < signal.length; i += 1) {
    prev += alpha * (signal[i] - prev);
    out[i] = prev;
  }
  return out;
}

const bass = lowpass(pcm, 160); // sub + kick
const lowMid = lowpass(pcm, 2000);
const mid = new Float32Array(n); // 160Hz - 2kHz
const treble = new Float32Array(n); // above 2kHz
for (let i = 0; i < n; i += 1) {
  mid[i] = lowMid[i] - bass[i];
  treble[i] = pcm[i] - lowMid[i];
}

const totalFrames = FPS * SECONDS;
const samplesPerFrame = RATE / FPS;

function framesRms(signal) {
  const out = new Float64Array(totalFrames);
  for (let f = 0; f < totalFrames; f += 1) {
    const start = Math.floor(f * samplesPerFrame);
    const end = Math.min(signal.length, Math.floor((f + 1) * samplesPerFrame));
    let sum = 0;
    for (let i = start; i < end; i += 1) sum += signal[i] * signal[i];
    const count = Math.max(1, end - start);
    out[f] = Math.sqrt(sum / count);
  }
  return out;
}

/** Normalise to 0-1 against the 98th percentile, then clamp — same posture as
 *  the bundled cue presets, so a single loud transient cannot flatten the rest. */
function normalise(values) {
  const sorted = Array.from(values).sort((a, b) => a - b);
  const p98 = sorted[Math.floor(sorted.length * 0.98)] || 1;
  return Array.from(values, (v) => Math.min(1, v / p98));
}

const bands = [framesRms(bass), framesRms(mid), framesRms(treble)].map(normalise);

const frames = [];
for (let f = 0; f < totalFrames; f += 1) {
  frames.push({
    bands: [
      Number(bands[0][f].toFixed(4)),
      Number(bands[1][f].toFixed(4)),
      Number(bands[2][f].toFixed(4)),
    ],
  });
}

writeFileSync(OUT, JSON.stringify({ fps: FPS, totalFrames, frames }));
const peak = Math.max(...frames.map((x) => x.bands[0]));
console.log(`wrote ${OUT}`);
console.log(`  ${totalFrames} frames @ ${FPS}fps · bass peak ${peak.toFixed(3)}`);
