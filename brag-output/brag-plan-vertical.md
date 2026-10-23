# Brag Plan — Ninsho **VERTICAL (9:16)** + **SQUARE (1:1)**

Run: `/brag --format vertical --tone cinematic --title Ninsho`
Narration: **off** (no `--voice` in the invocation).

Two cuts, because the placements have different physics:

| Cut | Size | Length | Where it goes | Why it differs |
| :-- | :-- | --: | :-- | :-- |
| `brag-vertical.mp4` | 1080x1920 | 25.65s | Reels · Shorts · TikTok | Platform chrome eats the top and bottom; content must live in a 1080x1220 band |
| `brag-square.mp4` | 1080x1080 | 20.19s | LinkedIn · X feed | Feeds autoplay **muted** — the argument has to land with no sound at all |

Neither is a crop of the landscape ad. Both are re-laid-out.

## What is this app?
A security-first authentication engine for Node.js — sessions, passkeys, token
rotation and proof-of-possession — where every security claim names the test
that demonstrates it.

## The angle
Unchanged from the landscape ad, because it works: **sell the pain.** Every
backend developer has shipped a "sign out everywhere" button that doesn't. We
show the lie, then show the fix working.

## Hook (first 5 seconds)
An account-security page with three sessions, one of them *"Unknown · Warsaw ·
4m ago"*. Cursor clicks **Sign out everywhere**. Green toast confirms it.

Then the card **lifts** and an attacker's terminal slides in underneath — and
this is the one place the vertical frame beats landscape outright. In 9:16 both
panels fit on screen at once, so the promise and the contradiction share the
final frame of the scene:

> *Signed out of all devices.* … `200 OK` — *the token you just revoked*

In the landscape cut the settings card had to slide away to make room. Here it
doesn't. The two halves of the lie sit stacked, which is a stronger frame.

## Key moments
- **The line.** "Your logout button is lying to you." — two lines, 94px serif.
- **The turn.** Logo punches in on the track's hardest measured hit (bass 0.92
  at 8.74s).
- **The demo.** Editor above, live request log below. Vertical is *better* at
  this than landscape: stacking reads top-to-bottom like a sequence, where
  side-by-side read as a comparison. Same token: `200` … then `401`.
- **The stack** (vertical only). Three benefit rows, each with its test file.
  Cut from four — mobile attention is shorter and the square drops it entirely.

## Outro / punchline
`2,056` counts up, then `$ npm i @ninshorg/server`, the mark, and *"Don't take
the claims. Run them."*

## User flow worth showing
Both cuts show two real flows: the **user's** (settings → sign out → toast,
immediately falsified) and the **developer's** (configure → revoke → next
request refused). This is the product in use, not a description of it.

## Tone
- Preset: `cinematic`
- Creative direction: *a problem-aware direct-response ad for people who already
  shipped the broken version.*
- Interpretation: cold and quiet for five seconds, then it never stops moving.

## Mobile safe area — the constraint that shaped the vertical layout
Reels, Shorts and TikTok overlay the frame:

```
   0 ─────────────────────  top chrome: profile, audio, follow
 230 ┌───────────────────┐
     │                   │
     │   SAFE CONTENT    │  1080 x 1220, x 70 → 1010
     │                   │
1480 └───────────────────┘
     ░░░░░░░░░░░░░░░░░░░░   caption, CTA, username
     ░░░░░░░░░░░░░░░░░ ▐▌   right rail: like / comment / share
1920 ─────────────────────
```

Every scene is centred inside that band via `padding: 260px 70px 440px` on the
clip, not inside the raw frame. The large empty area at the bottom of any still
is deliberate — it is where the platform draws, not wasted space.

## Format / duration
- **Vertical:** 1080x1920 @ 30fps — **25.65s**, every boundary on a beat.
- **Square:** 1080x1080 @ 30fps — **20.19s**, inside the 15–25s creative law.

> The vertical lands at 25.65s rather than 25.00s because the scene boundaries
> are locked to the track's beat grid (109.96 BPM) and the turn must sit on the
> 8.74s strong cue, which is where the music actually kicks. Rounding down to
> 25.00 would put every later cut off the beat to save 0.65s.

## Visual identity
Same tokens as the landscape ad — ground `#020D17`, panels `#0A2032`, seal
`#18ACFD`, pass `#3DDC97`, alarm `#FF6B63`, amber `#FFB454`; Instrument Serif /
Manrope / JetBrains Mono, all shipped locally. Secondary text uses `#8FA6BC`
rather than the site's `--faint`, which fails WCAG AA on the panel grounds.

## Audio direction
- Music: `bed.mp3` (vol-12, 109.96 BPM), chosen by profiling all five bundled
  tracks' energy curves against the ad arc.
- Volume lane: 0.30 under the pain → **0.98 at the turn** → 1.0 at the 401 →
  faded out by the end.
- Beat-locks (strong cues): **8.74** the turn · **13.11** the log arrives ·
  **15.84** the 401.
- Audio-reactive: measured per-frame bass breathes the ambient glow only.
- SFX: 21 cues (vertical), 16 (square), all motion-matched.
- **Square-specific rule:** no beat may be carried by sound alone. Feeds autoplay
  muted, so the click, the toast, the `200` and the `401` each have to read as a
  visual event. Audio is a bonus layer, never the carrier.

## Storyboard — vertical (as built)

| # | Scene | In → Out | What happens |
|---|---|---|---|
| 1 | **The pain** | 0 → 5.34 | Card centred; rows stagger (0.56); cursor clicks (1.64); toast (2.19); **card lifts, terminal slides in beneath (2.73)**; curl types (3.34); **`200 OK`** (4.39); *the token you just revoked* (4.70) |
| 2 | **Agitate** | 5.34 → 8.74 | "Your logout button / is lying to you." (5.34) · mechanism (6.56) · *6d 23h 58m* (7.64) |
| 3 | **The turn** | 8.74 → 10.93 | Burst + mark **(8.74 strong cue)** · "Auth that *proves* it works." (9.29) · 認証 (9.83) |
| 4 | **The demo** | 10.93 → 17.47 | Editor from above **(10.93)** · lines highlight (12.02 / 12.55) · log from below **(13.11)** · `200` (13.90) · `revokeAllForUser` (14.73) · **`401` (15.84)** · caption + cite (16.38) |
| 5 | **The stack** | 17.47 → 21.84 | Three rows on every other beat (17.47 / 18.56 / 19.66); ticks cascade (20.75 →) |
| 6 | **Proof + offer** | 21.84 → 25.65 | `2,056` **(21.84)** · install **(22.93 strong cue)** · mark (23.46) · *"Don't take the claims. Run them."* (23.90) |

## Storyboard — square (as built)
Identical through scene 4, then folds proof and offer together and **drops the
stack scene entirely** to stay inside the creative law:

| # | Scene | In → Out |
|---|---|---|
| 1 | The pain | 0 → 5.34 |
| 2 | Agitate | 5.34 → 8.74 |
| 3 | The turn | 8.74 → 10.93 |
| 4 | The demo | 10.93 → 16.93 |
| 5 | Proof + offer | 16.93 → 20.19 |

## Reading-time check
Vertical scene 5 is the tightest sequence at 1.09s apart, but rows **accumulate
and stay** — row 1 holds 4.4s. The longest reads (scene 2 headline, 7 words;
scene 4 caption, 10 words) hold 3.4s and 1.1s of settled time respectively, both
at or above the 0.3s-per-word floor.
