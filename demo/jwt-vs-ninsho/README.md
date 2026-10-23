# JWT vs Ninsho

One page, one account, two ways to stay signed in. Sign in on both sides, run
a scenario, and read the two results next to each other.

- **Left — JWT.** A signed token (HS256, 15 minutes) saved in `localStorage`.
  After signing it, the server remembers nothing.
- **Right — Ninsho.** A session checked in Redis on every request, bound to a
  key this browser holds but cannot export (DPoP). The access token lives in
  memory; the refresh token in an `HttpOnly` cookie.

Accounts are in Postgres and shared by both sides, so the only difference is
what happens after the password is accepted.

## Run it

You need Node 22+, Docker (for Redis) and a Postgres URL.

```bash
docker run -d --rm --name ninsho-redis -p 127.0.0.1:6380:6379 redis:7-alpine
cp env.example .env        # then put your DATABASE_URL in .env
npm install
npm test                   # checks every claim below against your Postgres and Redis
npm start                  # http://localhost:3100
```

The table `jvn_users` is created on first start. Nothing else in the database
is touched.

## The three scenarios

| Scenario | JWT | Ninsho | Test |
| --- | --- | --- | --- |
| 1. A copy taken before you sign out | Still works after sign-out (200) | Refused (401), even a complete request signed by the real device key | `app.test.ts` › *scenario 1* |
| 2. Token leaks while signed in | Works from the attacker's computer (200) | Token alone 401; signed with the thief's own key 401; key cannot be exported | `app.test.ts` › *scenario 2* |
| 3. Sign out of every device | Not possible; old tokens still work (200) | Every session ended; old requests 401 | `app.test.ts` › *scenario 3* |

"The attacker" is `POST /api/attacker/replay`: the server re-sends only the
stolen strings over a fresh connection, with no cookies and no device key. It
can only call this app's own `/api/*/me` endpoints.

## Honest limits

- A malicious script running **on this page** can act as the user while the
  page is open, on both sides. Ninsho stops it from carrying the login away;
  preventing the script is still the site's job.
- Ninsho does one Redis read per request; a JWT is checked with no lookup.
  That is the price of being able to end a session.
- The JWT side is a fair, common setup, not a broken one. JWTs *can* be made
  revocable with a denylist or session table, but then they need server state
  too, which is the trade Ninsho makes from the start.

## Files

- `src/db.ts` — Postgres accounts, scrypt password hashing
- `src/auth.ts` — the JWT signer and the Ninsho instance
- `src/app.ts` — routes, including the simulated attacker
- `src/app.test.ts` — the scenarios as tests (`node:test`)
- `public/` — the page (plain HTML, CSS and one module script)
