<!--
  Thank you for contributing.

  The checklist below is short because this project has exactly one rule, and
  most of the list is that rule applied. If something does not apply, say so
  rather than deleting the line — "n/a, this is a docs change" is a fine answer
  and tells a reviewer you read it.
-->

## What this changes

<!-- One paragraph. What was true before, what is true now. -->

## Why

<!--
  For a bug fix: what the wrong behaviour was, and how it was found. "Found by
  reading the code" is a legitimate answer; so is "found by clicking the
  playground panel". Saying how helps the next person look in the same place.

  For a security-relevant change: name the attack.
-->

## Evidence

<!--
  The rule: a security property stated in the documentation must name the test
  that demonstrates it. Name the test here — file and test name — and what it
  asserts.
-->

- Test:
- It asserts:

## Checklist

- [ ] `npm ci && npm run build && npm run test && npm run typecheck` passes
      locally — **build before typecheck**, or a clean checkout reports
      hundreds of errors
- [ ] Ran with a real Redis (`REDIS_URL=redis://localhost:6379 npm run test`),
      or this change cannot reach the store
- [ ] Every security-relevant change has a test that **fails without it** — I
      watched it fail
- [ ] Every bug fix has a regression test, marked `REGRESSION` with what the
      bug was
- [ ] No new runtime dependency in `@ninsho/core`, `@ninsho/client` or
      `@ninsho/webauthn`
- [ ] No environment variable that turns a check off
- [ ] No caught value interpolated into a client-facing `message` — that is
      what `detail` is for
- [ ] Changed a default? Updated `config.test.ts` › *secure defaults* and said
      why above
- [ ] Comments that explained the old behaviour now explain the new one

## Anything a reviewer should look at hardest

<!--
  Optional, and the most useful box on this form. Where are you least sure? A
  reviewer who knows where to concentrate finds more than one reading evenly.
-->
