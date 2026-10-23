# Brag Plan — Ninsho **SALES AD** (v2)

> v1 (`brag.mp4`) was an explainer: it told you what the library is. This is an
> **ad**: it makes you feel a problem you already have, shows the product solving
> it on screen, then asks for the install. Different job, different structure.

## What is this app?
A security-first authentication engine for Node.js — sessions, passkeys, token
rotation and proof-of-possession — where every security claim names the test
that demonstrates it.

## The angle
**Sell the pain, not the feature list.**

Every backend developer has shipped a "sign out everywhere" button. Almost none
of them work. With a self-contained token that nothing reads at verify time,
the button updates a row in a database and changes nothing about what the API
accepts. The user is told they are safe. They are not.

That is the ad. We show the lie, then show the fix working.

The product's own thesis — *claims must name their test* — is not the hook here.
It is the **credibility close**, which is where proof belongs in an ad.

## The ad structure
```
PAIN (0)  →  AGITATE (5.34)  →  TURN (8.74)  →  DEMO (11.46)
          →  STACK (18.56)   →  PROOF (24.56) →  OFFER (27.30)
```

## Hook (first 5 seconds) — the strongest decision in the piece
A real-looking account-security page. Three active sessions, one of them
**"Unknown device · Warsaw · 4m ago"**. A cursor moves to **Sign out
everywhere** and clicks it. Green toast: *"Signed out of all devices."*

Hard swap. The panel slides out; an attacker's terminal slides in, labelled
*"4 minutes later"*. A `curl` with the same bearer token types out. The response
lands in red:

**`HTTP/1.1 200 OK`** — *the token you just revoked · still accepted*

No narration, no claim. The viewer works it out themselves, which is why it
lands.

## Key moments (the middle)
- **The line.** "Your logout button is lying to you." Then the mechanism in one
  sentence, then the twist of the knife: *this session stays live for another
  6d 23h 58m.*
- **The turn.** Logo punches in on the track's hardest hit (measured bass 0.92
  at 8.74s). This is the only place the piece uses a burst.
- **The demo — the thing v1 was missing entirely.** Editor on the left, live
  request log on the right. Two lines of setup. Then `revokeAllForUser()`
  appears. Then the *same token* on the log: `200` … `401`. Caption:
  **"Revocation lands on the next request. Not the next expiry."** · `session.test.ts`
- **The stack.** Four benefit rows accumulating — inert stolen tokens, passkeys,
  six guards, four frameworks — each with its test file. Ticks cascade once all
  four have landed, confirming the set.

## Outro / punchline
`2,056` counts up. Then the credibility close: *"Every claim in this ad names
its test."* Then the offer, big: **`$ npm i @ninshorg/server`**, the mark, and
*"Don't take the claims. Run them."*

## User flow worth showing
**Yes, and it is the centrepiece** — this is the main upgrade over v1.
Scene 1 shows the *user's* flow (settings → sign out → toast) and immediately
falsifies it. Scene 4 shows the *developer's* flow (configure → revoke →
observe the next request refused). Both are the product in use, not a
description of it.

## Tone
- Preset: `cinematic`, driven harder than v1 toward `app-store` clarity in the
  demo and stack.
- Creative direction: *a problem-aware direct-response ad for people who already
  shipped the broken version.*
- Interpretation: Cold and quiet for five seconds, then it never stops moving.
  Directional motion throughout — panels enter from the side they argue from.
  The only restraint left is that nothing appears without a reason.

## Format: landscape — 1920x1080 @ 30fps
## Duration: **30.56 seconds**

> **Deliberate departure from the 15–25s creative law.** A full
> pain→agitate→turn→demo→proof→offer arc does not fit in 25s without cutting
> either the pain or the demo, and those are the two things that make it an ad
> rather than a feature list. 30s is also the standard ad slot. Scene boundaries
> all sit on the track's beat grid; the piece ends on beat 30.56.

## Visual identity (from the project)
- Ground `#020D17` → `#03111F`; panels `#0A2032`, chrome `#0F2B40`, borders `#17334A`
- Accent `#18ACFD` · cyan `#11D8FE` · pass `#3DDC97` · alarm `#FF6B63` · amber `#FFB454`
- Text `#F2F7FB` / dim `#A8BCCD` / quiet `#8FA6BC` *(lifted from the site's
  `--faint`, which fails WCAG AA on the lighter panel grounds)*
- Instrument Serif (display) · Manrope (UI) · JetBrains Mono (all code and evidence)
- Recreated from the site: the terminal card with mac dots, the `.cite`
  claim/citation pair, the card grid

## Audio direction
- Music: `assets/music/bed.mp3` (vol-12, 109.96 BPM). **Chosen by measurement,
  not by ear** — its energy curve was profiled against the ad arc and it is the
  only one of the five bundled tracks that is quiet for the first six seconds
  (0.41–0.49) and peaks at the offer (0.90–1.00 at 24–30s).
- Volume lane: 0.30 under the pain → **0.98 at the turn** → 1.0 through demo and
  stack → ducked to 0.70 for the counter → out by 30.56.
- Beat-locks (strong cues): **8.74** the turn · **13.64** the log arrives ·
  **15.84** the 401 · **24.56** the count · **27.30** the CTA.
- Audio-reactive: subtle. Measured per-frame bass drives the ambient glow only.
- SFX: 24 cues, all motion-matched. Cursor click, toast drop, panel swap,
  keystrokes on the curl, a metal hit on the `200 OK`, the kick on the logo, a
  heavy hit on the `401`, four row slides, two cascade stamps, counter settle,
  final impact.
- Restraint rule (unchanged from v1): **no sound plays without a visual event
  under it.**

## Storyboard (as built — absolute times)

| # | Scene | In → Out | What happens |
|---|---|---|---|
| 1 | **The pain** | 0 → 5.34 | Settings card; rows stagger; cursor clicks *Sign out everywhere* (1.64); toast (2.19); **hard swap** (2.73); curl types (3.34); **`200 OK`** (4.39); *still accepted* (4.76) |
| 2 | **Agitate** | 5.34 → 8.74 | "Your logout button is lying to you." (5.34) · mechanism (6.56) · *6d 23h 58m* (7.64) |
| 3 | **The turn** | 8.74 → 11.46 | Burst + mark punch **(8.74, strong cue — the track's hardest hit)** · "Auth that *proves* it works." (9.29) · 認証 sub (10.37) |
| 4 | **The demo** | 11.46 → 18.56 | Editor in from left (11.46) · lines highlight (12.55 / 13.11) · log in from right **(13.64)** · `200` (14.20) · `revokeAllForUser` (14.73) · **`401` (15.84)** · why (16.38) · caption + cite (16.93) |
| 5 | **The stack** | 18.56 → 24.56 | Four rows slide in on every other beat (18.56 / 19.66 / 20.75 / 21.84); ticks cascade (22.37 → 23.21) |
| 6 | **Proof** | 24.56 → 27.30 | `2,056` counts up **(24.56)** · supporting line (25.65) · *"Every claim in this ad names its test."* (26.20) |
| 7 | **The offer** | 27.30 → 30.56 | Mark **(27.30)** · **`$ npm i @ninshorg/server`** (27.52) · *"Don't take the claims. Run them."* (28.37) · links (28.92) |

**Total: 30.56s** — every boundary on a beat.

## Reading-time check
The stack rows are the tightest sequence at 1.09s apart, but they **accumulate
and stay on screen** — row 1 is visible for 6.0s, row 4 for 2.7s. The two longest
reads (the scene-2 headline at 7 words, the scene-4 caption at 9) hold 3.4s and
1.6s respectively, both above the 0.3s-per-word floor.
