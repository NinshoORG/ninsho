# CLAUDE.md

**Read [`AGENTS.md`](./AGENTS.md).** It is the canonical context document for
this repository and is kept deliberately as the single source, so that guidance
cannot drift between one agent's file and another's.

This file exists only because Claude Code looks for it by name. Everything you
need — the rule this project runs on, the repository map, the commands, the
invariants CI enforces, the conventions, and the traps that have already cost
real time — is there.

Two things worth having in mind before you start, both expanded in `AGENTS.md`:

1. **A security property stated in the documentation must name the test that
   demonstrates it, or it does not get stated.** This is the reason the project
   exists. It applies to comments and commit messages as much as to READMEs.

2. **`npm run build` before `npm run typecheck` or `npm run test`.** A fresh
   checkout produces 227 typecheck errors otherwise, because `@ninshorg/server`
   resolves `@ninshorg/core` through its built output.
