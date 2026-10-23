# Hyperframes Composition Brief: Ninsho (認証)

## Objective
Create a short launch-style brag video for Ninsho, a security-first
authentication engine for Node.js.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080 @ 30fps
- Duration: 23.5 seconds

## Source Material
- Project root: `C:\Users\djain\Desktop\JWT\Ninsho`
- Primary files read: `website/index.html`, `website/assets/style.css`,
  `README.md`, `PERFORMANCE.md`, `website/assets/brand/*`
- Product name: Ninsho (認証)
- Tagline / strongest claim: **"Auth that proves it works."**
- Key UI / visual moment to recreate: the site's `.cite` device — a claim
  followed immediately by a monospace test filename. This is the product's
  founding rule rendered as layout, and it is the video's entire visual grammar.
- Copy that must appear verbatim (all of it is real project copy):
  - `"instant revocation"` / `"all attacks blocked"` / `"110 tests passing"` — the
    predecessor library's claims, quoted from the audit lineage
  - "Auth that **proves** it works."
  - "A security claim must name the test that demonstrates it."
  - "Token theft, replayed" · `session.test.ts`
  - "Access token copied out" · `dpop-integration.test.ts`
  - "One account, thousands of hosts" · `ratelimit.test.ts`
  - "Password reset, used twice" · `ott-race-probe.test.ts`
  - "Reading someone else's orders" · `middleware.test.ts`
  - "Redis goes down mid-attack" · `store-invariants.test.ts`
  - `2,056` tests · `npm i @ninshorg/server`
  - "Don't take the claims. Run them."

## Creative Direction
- Tone preset: `cinematic`
- Creative direction: *a forensic exhibit reel — every claim answered on screen
  by the file that proves it.*
- Interpretation: Big display type, dramatic holds, restrained motion. Energy
  comes from hard stamps and hard cuts, never from clutter. The edit should feel
  like evidence entered under oath.
- Angle: Most auth libraries make claims. This one makes a claim and
  immediately shows the receipt. The hook is a confession — the predecessor
  library made all the same claims and every one of them was unverified — which
  is what makes the video specific to this project and not generic security
  marketing.
- Hook: three of the predecessor's claims type in, dim and monospace; a red rule
  strikes all three at once and the word **UNVERIFIED** lands.
- Outro / punchline: `$ npm i @ninshorg/server` types out, then the site's own
  closing line — **"Don't take the claims. Run them."**
- Avoid:
  - Generic SaaS language
  - Abstract filler visuals
  - Unrelated visual redesign
  - Any claim on screen without its test filename beside it

## Visual Identity
- Background: `#020D17` (`--void`) into `#041526` (`--ground`)
- Surface / cards: `#0A2032`, borders `#17334A`
- Text: `#F2F7FB` (`--ink`), dim `#9FB3C6`, faint `#6B8298`
- Accent: `#18ACFD` (`--seal`), secondary `#11D8FE`
- Pass mark: `#3DDC97` (`--pass`); alarm `#FF5F57` (hook strike only)
- Display font: **Instrument Serif** — shipped locally at `assets/fonts/`
- Body font: **Manrope** — shipped locally
- Mono font: **JetBrains Mono** — shipped locally; carries every citation
- Visual references from the project: the `.cite` claim/citation pair, the
  hero terminal card with mac dots, the 3-column attack card grid, the
  `ninsho-lockup-on-dark.png` mark

## Storyboard
`brag-output/brag-plan.md` is the creative contract.

Scene summary (absolute times, beat-aligned to the chosen track):
1. **The false claims** — 0.00→3.82s — three quoted predecessor claims, struck
   through; **UNVERIFIED**
2. **The answer** — 3.82→7.09s — lockup resolves; "Auth that *proves* it works."
3. **The rule** — 7.09→10.93s — "A security claim must name the test that
   demonstrates it." then the citation stamps beneath it
4. **Six attacks, six receipts** — 10.93→17.47s — three cards arrive one by one,
   each answered by its test file with a pass mark; remaining three snap in to
   complete the grid
5. **The number** — 17.47→20.20s — `2,056` counts up; packages, dependencies,
   7/7 attestation formats
6. **Run them** — 20.20→23.50s — install command types; closing line

## Audio
- Audio role: cinematic support
- Audio arc: tense and quiet under the discredited claims → hard verdict on the
  strike → release at the logo → accumulating momentum through the attack
  sequence → ducked for the counter → faded to near-silence for the closing line
- Music: `assets/music/bed.mp3`
  (`happy-beats-business-moves-vol-12-by-ende-dot-app.mp3`, 109.96 BPM)
- Music treatment: `data-automation` volume lane — 0.25 under the hook, lift to
  0.85 at the logo, 0.95 through the attack grid, duck to 0.55 under the
  counter, recover, then fade to 0 across the final 1.5s.
- Music cue guidance: bundled preset read from
  `assets/music/bed.cues.json`. Beat grid 0.546s. **Three strong-cue locks:**
  `10.93` (attack sequence begins), `15.84` (grid completes), `17.47` (the
  number). Sequential attack cards sit on **every third beat** (10.93 / 12.55 /
  14.20, ~1.63s apart) rather than every beat, because each card carries a
  filename that must be readable.
- Audio-reactive treatment: **subtle.** Real per-frame band energy extracted
  from the track (`assets/music/bed.audio-data.js`, 720 frames @ 30fps, three
  bands). Bass drives the ambient seal glow's opacity and scale; mid drives a
  small card-grid presence lift during scene 4. No waveform bars, no meters, no
  strobing.
- Audio-coupled moments:
  - Scene 1 — three claims arriving (soft tick each), the strike (one heavy hit)
  - Scene 2 — logo landing (deep impact, beat-locked)
  - Scene 3 — the citation stamp
  - Scene 4 — one stamp per citation; a tighter hit on grid completion
  - Scene 5 — counter settle
  - Scene 6 — keyboard ticks on the typed install command; final soft impact
- SFX selection guidance: sounds match motion and interaction only. The
  *citation* is what makes the sound in scene 4, not the card arrival — the
  evidence is the event.
- SFX analysis guidance: `.agents/skills/brag/assets/sfx/sfx-analysis.md`. All
  repeated cues use **low high-frequency-risk** files
  (`impactSoft_medium_001`, `click2`) so four stamps in six seconds do not
  fatigue.
- Exact SFX choice: made after the animation existed, per the brief's contract.
- Audio files: copied into `composition/assets/music/` and
  `composition/assets/sfx/`.

## Hyperframes Instructions
Built against `hyperframes-core` (composition contract, `data-*` timing),
`hyperframes-animation` (motion), `hyperframes-creative` (audio-reactive,
typography), `hyperframes-keyframes`, `hyperframes-cli` (check/render).

Requirements met:
- Real project copy and a recreated UI element (terminal card, attack card grid,
  cite lines) — all lifted from `website/index.html`.
- Every text element holds at or above the reading-time floor.
- 23.5s, inside the 15–25s window.
- Music + SFX layer present; volume automation lane authored.
- Fonts shipped locally with `@font-face` to real files — no network fonts.
- `hyperframes check` is the gate before render.
