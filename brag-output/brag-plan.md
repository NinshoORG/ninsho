# Brag Plan: Ninsho (認証)

## What is this app?
A security-first authentication engine for Node.js — sessions, passkeys, token
rotation and proof-of-possession — built on one founding rule: every security
claim in the documentation must name the executable test that demonstrates it.

## The angle
**Evidence, not adjectives.** Most auth libraries make claims. This one makes
claims *and immediately shows the receipt.* The video's entire visual grammar is
that transaction: a bold claim lands, and a monospace test filename stamps in
underneath it like a court exhibit stamp. The site already does this — `.cite`
is its signature CSS device — so the video is the product's own thesis in motion.

The hook is the confession: the predecessor library claimed all the same things
and every claim was false. That's what makes this specific and not generic
security marketing.

## Hook (first 2.5 seconds)
Near-black. Three claims from the *predecessor* library type in fast, dim and
monospace — `"instant revocation"`, `"all attacks blocked"`, `"110 tests passing"`.
They hold for a beat. Then a red strike cuts all three at once and one word
lands: **UNVERIFIED.**

That's the earned 20 seconds: it opens with a failure, not a feature.

## Key moments (the middle)
- **The rule, in full serif.** "A security claim must name the test that
  demonstrates it." Then the monospace cite stamps under it. The thesis stated
  once, plainly, and cited — the video obeys its own rule.
- **Six attacks, one by one.** The centerpiece. Each attack name arrives, then
  its evidence line stamps in with a pass mark: stolen refresh token →
  `session.test.ts`; XSS exfiltration → `dpop-integration.test.ts`; botnet
  credential stuffing → `ratelimit.test.ts`. Then the remaining three snap in to
  complete a 6-card grid that holds.
- **The count.** `2,056` ticks up on a counter. Not "comprehensive testing" —
  a number, with the packages and the 7-of-7 WebAuthn attestation formats beside it.

## Outro / punchline
Terminal: `npm i @ninshorg/server` with a blinking cursor. Logo resolves. The
site's own closing line, which is also the only correct call to action for a
project built on this rule: **"Don't take the claims. Run them."**

## User flow worth showing
The demonstration playground: **click an attack → watch it lose → read the store
operations printed underneath, with the test file named.** Scene 4 is that flow
compressed — the attack card is the entry, the pass mark is the result, and the
monospace filename is the receipt. This is the product *doing* its thing, not
describing it.

## Tone
- Preset: `cinematic`
- Creative direction: *a forensic exhibit reel — every claim answered on screen
  by the file that proves it.*
- Interpretation: Big display type, dramatic holds, restrained motion. Energy
  comes from hard stamps and cuts, never from clutter. The video must feel like
  it is presenting evidence under oath, which is exactly the product's posture.

## Format: landscape — 1920x1080 @ 30fps
## Duration: 23.5 seconds

> **As-built note.** Scene boundaries below are the final ones, moved from the
> first draft's round numbers onto the chosen track's actual beat grid
> (109.96 BPM, 0.546s). That shifted the total from 22.0s to 23.5s. Three
> strong-cue locks: 10.93s, 15.84s, 17.47s.

## Visual identity (from the project)
- Background: `#020D17` (`--void`, dark theme) → `#041526` (`--ground`)
- Surface / cards: `#0A2032` (`--surface`), raised `#0F2B40`
- Accent (the seal): `#18ACFD` (`--seal`), secondary cyan `#11D8FE`
- Pass mark: `#3DDC97` (`--pass`)
- Alarm (hook strike only): `#FF5F57`
- Text: `#F2F7FB` (`--ink`), dim `#9FB3C6`, faint `#6B8298`
- Display font: **Instrument Serif** (headlines)
- Body font: **Manrope**
- Mono font: **JetBrains Mono** — carries every citation; non-negotiable
- Strongest visual element: the `.cite` line — a claim followed by a monospace
  test filename. Brand assets at `Ninsho/website/assets/brand/`
  (`ninsho-lockup-on-dark.png`, `ninsho-icon.png`).

## Share copy (draft)
Most auth libraries tell you they're secure. Ninsho names the test file. 2,056 of
them. `npm i @ninshorg/server`

## Audio direction
- Role: cinematic support — a low bed that holds tension under the hook, opens at
  the logo, and drives the attack sequence.
- Music: bundled upbeat/business track, treated dark — start low, swell at the
  reveal, full through the attack grid, fade under the outro terminal.
- Music treatment: fade-in over the hook, lift on the logo impact, duck ~3 dB
  under the counter, fade out across the last 1.5s so the final line reads in
  near-silence.
- Music cue guidance: read the bundled preset from `assets/music/cues/`; target
  strong cues at the **UNVERIFIED** strike (~2.2s), the **logo impact** (~3.2s),
  and the **first attack card** (~10s). Sequential attack cards should sit on a
  beat grid of **every other beat**, not every beat — each card carries a
  filename that must be readable (~1.2s settled minimum).
- Audio-reactive treatment: subtle. Let bass energy breathe the seal glow behind
  the logo and the card grid's ambient presence. No waveform bars, no meters.
- SFX posture: sparse and motion-matched. Dry ticks on the three false claims, a
  single hard hit on the strike, one deep impact on the logo, a soft mechanical
  stamp per citation, a light tick per counter digit.
- Audio-coupled moments: the three claims typing in; the red strike; the logo
  resolve; each of six citation stamps; the 2,056 count-up; the terminal cursor.
- Restraint rule: **no sound may play that has no visual event under it.** No
  risers for their own sake, no whooshes between every cut. The audio must be as
  evidence-bound as the copy — if nothing is happening on screen, nothing plays.

## Storyboard

*(As built. Absolute times; each scene is a `.clip` with `data-start` /
`data-duration` in `composition/index.html`.)*

### Scene 1 — The false claims (HOOK) — 0.00 → 3.82s
Near-black `#020D17`. Eyebrow in mono: `THE LIBRARY THIS ONE REPLACES SAID:`.
Three dim monospace lines stagger in fast, stacked and centred:
`"instant revocation"` / `"all attacks blocked"` / `"110 tests passing"`. They
read as one block, then hold 1.6s. At **2.73s** a red `#FF5F57` rule strikes
through all three simultaneously, the lines drop to 32% opacity, and
**UNVERIFIED** slams in beneath them.
Sequential/interaction: yes — claims at 0.56 / 0.82 / 1.09s (fast stagger, read
as a block); the strike is one simultaneous event across all three.
Audio intent: uneasy and quiet, then a hard verdict.
Audio-coupled: soft tick per claim; one heavy hit on the strike.
Music: low bed at 0.22 gain, rising to 0.34.
Transition: hard cut → Scene 2

### Scene 2 — The answer (REVEAL) — 3.82 → 7.09s
Lockup resolves centre from 0.9 scale with the ambient seal glow behind it.
Headline in Instrument Serif 116px: **Auth that _proves_ it works.** — "proves"
in `--seal`. Beneath: `認証 · authentication engine for Node.js`.
Sequential/interaction: none — one confident resolve.
Audio intent: arrival. The tension from Scene 1 releases.
Audio-coupled: deep impact exactly on the logo landing. **beat-locked 3.82s.**
Music: lifts to 0.86.
Transition: clean → Scene 3

### Scene 3 — The rule — 7.09 → 10.93s
Two centred Instrument Serif lines: **"A security claim must name / the test
that demonstrates it."** Settles and holds 2.2s. Then a hairline draws
left-to-right and the citation stamps beneath it:
`enforced in review · CONTRIBUTING.md`.
Sequential/interaction: yes — headline first, *then* rule, *then* cite. The
order is the thesis: claim, then evidence.
Audio intent: weight and stillness.
Audio-coupled: soft mechanical stamp on the citation at 9.83s.
Music: eases back to 0.68 — restraint, no percussion spike.
Transition: hard cut → Scene 4

### Scene 4 — Six attacks, six receipts (CENTREPIECE) — 10.93 → 17.47s
Mono label `WHAT IT STOPS` left, `6 ATTACKS · 6 TEST FILES` right. Cards arrive
on a 3x2 grid, each in two stages — attack name, then the evidence line stamping
in beneath with a green tick and the test filename:
1. **Token theft, replayed** → `entire family revoked` · `session.test.ts`
2. **Access token copied out** → `inert without the key` · `dpop-integration.test.ts`
3. **One account, thousands of hosts** → `per-account bucket` · `ratelimit.test.ts`
Then the remaining three complete the grid together — *Password reset used
twice* (`ott-race-probe.test.ts`), *Reading someone else's orders*
(`middleware.test.ts`), *Redis goes down mid-attack* (`store-invariants.test.ts`)
— and all six hold ~1.5s with every pass mark lit.
Sequential/interaction: yes — cards 1-3 on **every third beat** (10.93 / 12.55 /
14.20, ~1.63s apart) so each filename is readable; cards 4-6 snap in together at
15.84s as one completion beat.
Audio intent: momentum and accumulation — the case built exhibit by exhibit.
Audio-coupled: one stamp per citation (11.46 / 13.08 / 14.73s); a tighter hit on
grid completion. **The citation makes the sound, not the card arrival — the
evidence is the event.** **beat-locked 10.93s and 15.84s.**
Music: full at 0.96, beat-aligned to the card arrivals.
Transition: hard cut → Scene 5

### Scene 5 — The number — 17.47 → 20.20s
A single huge mono counter ticks **0 → 2,056** in 1.06s and settles. Label
beneath: `tests, against real Redis`. Then one mono line:
`4 packages · 0 runtime dependencies in 3 of 4 · 7/7 WebAuthn attestation formats`.
Sequential/interaction: yes — counter settles first, then the stat line lands and
holds 1.6s.
Audio intent: precision. A number, not a boast.
Audio-coupled: one soft cue on the settle at 18.56s.
Music: ducked to 0.52 under the count-up, recovering to 0.78.
**beat-locked 17.47s.**
Transition: clean → Scene 6

### Scene 6 — Run them (OUTRO) — 20.20 → 23.50s
Terminal card with mac dots, titled `install`. `$ npm i @ninshorg/server` types
character by character with a blinking seal cursor. The terminal lifts away and
the lockup rises with the closing line in Instrument Serif: **"Don't take the
claims. Run them."** Footer: `github.com/NinshoORG/ninsho · MIT · npm i @ninshorg/server`.
Sequential/interaction: yes — the install command types out, then the closing
line resolves.
Audio intent: settled and done. The last line lands in near-silence.
Audio-coupled: keyboard ticks across the typed command (20.36-21.24s); one final
soft impact on the lockup at 21.50s.
Music: fades from 0.66 to 0 across the final 1.5s.
Transition: holds to end.

**Scene durations:** 3.82 + 3.27 + 3.84 + 6.54 + 2.73 + 3.30 = **23.50 seconds**

**Music mood:** cinematic — dark and tense at the open, driving and precise
through the attack sequence, resolving quiet.

**Audio summary:** The audio arc mirrors the argument — uneasy under the
discredited claims, a hard verdict on the strike, release at the logo,
accumulating momentum as each attack is answered by its test file, then a
deliberate fade so the closing instruction is delivered almost dry.
