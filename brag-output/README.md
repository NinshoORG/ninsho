# Ninsho — launch video set

Four cuts, built with `/brag` + Hyperframes. Every figure and filename on screen
is real and checkable against the repo, which is the same rule the library runs
on.

| File | Size | Length | Use it for | Concept |
| :--- | :--- | ---: | :--- | :--- |
| `brag-ad.mp4` | 1920x1080 | 30.6s | Landing page hero, YouTube, demo day, README embed | **Sales ad** — pain → agitate → turn → live demo → proof → offer |
| `brag-vertical.mp4` | 1080x1920 | 25.7s | Reels · Shorts · TikTok | Same ad, re-laid-out for 9:16 inside the platform safe area |
| `brag-square.mp4` | 1080x1080 | 20.2s | LinkedIn · X feed | Same ad, tightened; **built to read with the sound off** |
| `brag.mp4` | 1920x1080 | 23.5s | Docs, conference talk, technical audience | **Explainer** — the evidence-binding thesis, six attacks, six test files |

Each `.mp4` has its poster baked as frame 0, so Slack, X and Discord thumbnail it
correctly instead of grabbing a black intro frame. The matching `.jpg` is the
upload asset for platforms that accept a custom cover (Instagram, TikTok,
YouTube, LinkedIn).

## Which one to post

- **Someone asked "what does it do?"** → `brag-ad.mp4`
- **Posting to a phone-first feed** → `brag-vertical.mp4`
- **Posting where autoplay is muted** → `brag-square.mp4`
- **Talking to people who will read the test names** → `brag.mp4`

## The ad's argument

> You ship a "sign out everywhere" button. A user clicks it and gets a green
> toast. Four minutes later the same token still returns `200`, because a
> self-contained token that nothing reads at verify time is valid until it
> expires. Revocation changed a row in your database and nothing about what your
> API accepts.

Ninsho reads the store on every request, so revocation lands on the **next
request**. The ad shows that happening — `200`, then `revokeAllForUser()`, then
`401` on the same token — rather than asserting it.

## Sources

- `brag-plan-ad.md` — landscape ad plan and storyboard
- `brag-plan-vertical.md` — vertical + square plan, incl. the mobile safe-area map
- `brag-plan.md` — original explainer plan
- `composition-brief-ad.md` — the Hyperframes handoff brief
- `share-copy-ad.txt` — X, LinkedIn, HN and Shorts copy
- `share-copy.txt` — copy for the explainer cut

## Rebuilding

```bash
cd brag-output/<composition-dir>
PATH="../.bin:$PATH" ../node_modules/.bin/hyperframes check
PATH="../.bin:$PATH" ../node_modules/.bin/hyperframes render \
  --output ../<name>.mp4 --quality delivery --low-memory-mode
```

Three things about this machine that are not obvious and cost real time:

1. **`--low-memory-mode` is required.** A default render buffers every frame to
   disk and wants ~5.8 GB of scratch for a 30s 1080p cut. C: does not have it.
   Without the flag the render dies at 25%.
2. **FFmpeg is not on PATH.** `ffmpeg-static` / `ffprobe-static` are installed
   into `brag-output/` and both binaries copied to `brag-output/.bin/`. Prepend
   that directory before any `check`, `snapshot` or `render`.
3. **Never pipe `render` into `tail`.** The pipeline returns tail's exit code, so
   a failed render reports success and you get no file.

## Assets

- Music: `happy-beats-business-moves-vol-12` (109.96 BPM), bundled with `/brag`.
  Chosen by profiling all five bundled tracks' energy curves against the ad arc
  rather than by ear — it is the only one quiet through the first six seconds and
  peaking at the offer.
- Audio-reactive data: `extract-audio-data.mjs` pulls real per-frame band energy
  with ffmpeg (the Hyperframes extractor needs Python + librosa, which this
  machine does not have).
- Fonts: Instrument Serif, Manrope, JetBrains Mono — shipped locally per project,
  no network fetch at render time.
- Logo: cropped from `website/assets/brand/ninsho-lockup-on-dark.png` to the
  card bounds (725x234 at 15,15) and re-rounded in CSS.

  **Note:** that file is misnamed. It is `rgb24` with no alpha and white corners
  — the *light*-background variant. It is currently selected by the README's
  `<picture>` block for `prefers-color-scheme: dark`, where it paints a white box
  behind the mark. Worth fixing at source.
