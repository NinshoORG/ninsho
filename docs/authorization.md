# Authorization

Authentication answers *who is this*. Authorization answers *may they do **this***
— and it is the half applications usually write by hand at each call site, which
is why broken object-level authorization has sat at number one on the OWASP API
Security Top Ten for as long as the list has existed.

Ninsho ships six guards. Every one of them is middleware, every one runs after
`verify()`, and every one refuses rather than guesses when it cannot answer.

> **Watch them run.** The playground's *Authorization* panel drives all six
> against real tokens and prints what the caller was told beside what the audit
> trail recorded. `npm run dev --workspace @ninsho/playground`, panel 3.

---

## Mount `verify()` first

```ts
app.get('/admin/users',
  auth.verify(),               // populates req.auth
  auth.requireRole('admin'),   // reads req.auth
  handler);
```

`getAuth(req)` **throws** if `verify()` has not run, rather than returning
`undefined`. That turns a middleware-ordering mistake into a loud failure on the
first request, instead of `req.auth?.userId` quietly evaluating to nothing and an
authorization check comparing against it.

Read the identity in your handler with `getAuth(req)`:

```ts
import { getAuth } from '@ninsho/server';

app.get('/me', auth.verify(), (req, res) => {
  const { userId, roles, scopes, tenant, sessionId, tokenId,
          issuedAt, authenticatedAt } = getAuth(req);
  res.json({ userId, roles });
});
```

---

## 401 and 403 are different answers

| | | |
| --- | --- | --- |
| **401** | `verify()` | The server does not know who you are. No token, or a token it will not accept |
| **403** | a guard | The server knows who you are, and the answer is still no |

A library that returned one for both would make an unauthenticated request
indistinguishable from an unauthorized one — a debugging problem for you and an
information problem in the other direction.

*Evidence: `middleware.test.ts`.*

---

## The guards

### `requireRole(roles)` — any of

```ts
auth.requireRole('admin')
auth.requireRole(['admin', 'support'])
```

Passes if the caller holds **at least one** of the named roles. Matching is
exact — never a prefix, never a wildcard.

An empty list is refused **at construction**, not at request time. A guard that
permits everyone while reading as a restriction is worse than no guard.

### `requireAllRoles(roles)` — all of

```ts
auth.requireAllRoles(['admin', 'security-officer'])
```

Passes only if the caller holds **every** named role. The distinction from
`requireRole` is why both exist: "any of these" and "all of these" are different
questions, and a call site that reaches for the wrong one still reads correctly.

### `requireScope(scopes)` — any of

```ts
auth.requireScope('orders:write')
auth.requireScope(['orders:write', 'orders:admin'])
```

Roles and scopes are **independent axes**. A role is who someone is; a scope is
what this credential may do. Holding `admin` does not imply holding
`orders:write`, and this guard will refuse an administrator who lacks the scope.

That is deliberate and it is the point: a scope check that quietly waved through
anyone holding an admin role would turn every narrowly delegated token into a
full one.

### `requireOwner(selector)` — object-level access

```ts
app.get('/users/:id/orders',
  auth.verify(),
  auth.requireOwner((req) => req.params?.id),
  handler);
```

The check that closes OWASP API Security #1. Every request it refuses carries a
**valid, unexpired, unrevoked token** — that is the whole difficulty.
Authentication cannot answer this, because nothing is wrong with the credential;
the request is simply for somebody else's data.

Four ways it refuses, and the last three are the ones worth understanding:

| The selector returns | Result | Why |
| --- | --- | --- |
| Someone else's id | **403** | The obvious case |
| `undefined` | **403** | A selector pointing at a renamed route parameter returns nothing. Treating that as a pass would silently disable the check across every route using it — and its happy-path test would keep passing |
| An **array** | **403** | Express 5 route parameters can be repeatable, so a selector really can receive several matched segments. Several segments are not one owner, and picking an element invents an answer the route never asked for |
| A thrown error | **403** | A throwing selector is not permission |

The refusal message is deliberately vague. Naming the owner would confirm the
resource exists and belongs to someone, which is an enumeration oracle. The
reason is kept in the audit trail instead, where it is useful and not readable
by the caller.

> **Do not add a convenience that unwraps a one-element array.** `['user_alice']`
> is still not `'user_alice'`, and unwrapping it is the change that looks
> harmless and reintroduces the rest.

*Evidence: `middleware.test.ts` › `requireOwner`, and › *a repeatable route
parameter*.*

### `requireTenant(selector)` — multi-tenant isolation

```ts
app.get('/t/:tenant/orders',
  auth.verify(),
  auth.requireTenant((req) => req.params?.tenant),
  handler);
```

The caller's `tenant` claim must match the tenant being addressed. A genuine
admin of one organisation gets nothing at another — the role is real and
irrelevant.

**A token with no tenant claim never passes**, on any path. In a tenanted
deployment an absent tenant means the token predates tenanting or was minted by
a misconfigured path, and neither should reach tenant-scoped data.

The same selector rules apply as `requireOwner`: absent, arrayed and thrown are
all refusals.

### `requireFreshAuth(maxAgeSeconds)` — step-up

```ts
app.post('/account/email',
  auth.verify(),
  auth.requireFreshAuth(300),      // authenticated in the last five minutes
  handler);
```

For operations where being signed in should not be sufficient: changing an email
address, adding a passkey, moving money.

**It reads `authenticatedAt`, not `issuedAt`.** That distinction is the entire
mechanism:

- `issuedAt` is when *this token* was minted, and rotation mints a new one every
  few minutes for as long as the session lives. A session refreshed for thirty
  days has an `issuedAt` that is always minutes old.
- `authenticatedAt` is when the user actually proved who they are, and a refresh
  does not move it.

So refreshing will **never** satisfy this check. Only signing in again — and
calling `createSession` afresh — will. If it read the token's age instead, a
stolen refresh token would buy an attacker a step-up they never passed.

A failure here does **not** end the session. Ordinary routes keep working; the
session simply stopped being fresh enough for this one operation. A step-up
refusal that signed the user out would be a denial of service wearing a security
feature's clothes.

A non-positive `maxAgeSeconds` is refused at construction — it would reject
every request while reading as a freshness requirement. An unparseable
authentication time fails closed, as every other time comparison here does.

*Evidence: `fresh-auth.test.ts` — in particular › *will not let a refresh satisfy
a check the session had failed*.*

---

## What every refusal writes

Each guard emits an `authz.denied` event before throwing:

```json
{
  "type": "authz.denied",
  "at": "2026-09-07T01:08:23.962Z",
  "userId": "usr_alice",
  "sessionId": "o16bmoLO4fmyJablMGB_9A",
  "reason": "caller does not own the requested resource"
}
```

The `reason` is what the *server* knows. The caller gets "Insufficient
permissions" and nothing else. Comparing those two side by side is the clearest
way to see the separation, which is exactly why the playground prints both.

A burst of `authz.denied` for one `userId` across many resources is worth an
alert — that is what enumeration looks like from the inside.

---

## Composing guards

Guards are ordinary middleware and compose in the order you mount them. The
first to refuse ends the request.

```ts
app.delete('/t/:tenant/users/:id',
  auth.verify(),
  auth.requireTenant((req) => req.params?.tenant),
  auth.requireRole('admin'),
  auth.requireFreshAuth(300),
  handler);
```

Put the cheapest and broadest check first. All of these are in-memory
comparisons against `req.auth` — only `verify()` touches the store — so the
ordering is about clarity rather than cost.

---

## What Ninsho does not do here

- **No policy language, no rules engine.** Six guards, mounted explicitly at
  the route. If your authorization needs a DSL, it needs code you own rather
  than a configuration format the library interprets.
- **No implicit hierarchy.** `admin` does not inherit `user`. Roles are exact
  strings, because an inheritance rule invisible at the call site is a rule
  nobody reviews.
- **No wildcard scopes.** `orders:*` matches nothing. A prefix match is an easy
  thing to get subtly wrong and a hard thing to notice.
- **No row-level filtering.** `requireOwner` answers "may this caller address
  this identifier". Which rows a query returns is your application's job.
