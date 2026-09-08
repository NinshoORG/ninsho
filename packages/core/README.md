# @ninshorg/core

Shared types, error taxonomy, and cryptographic primitives for
[Ninsho](https://github.com/NinshoORG/ninsho).

**Zero runtime dependencies.** Everything here is built on `node:crypto`, which
is enforced in CI: the build fails if this package's bundle requires anything
else.

## You probably want `@ninshorg/server`

Application code should install `@ninshorg/server`, which re-exports everything
here. Depend on this package directly only when sharing types across a boundary
— for example between a server and a future browser client.

```bash
npm install @ninshorg/core
```

## What is in it

**Types** — `Principal`, `AuthContext`, `TokenPair`, `RefreshRecord`,
`PasetoClaims`, `KeySet`, `SecurityEvent`, and the `TokenStrategy` /
`BindingMode` / `FailureMode` selectors.

**Errors** — `NinshoError` and eleven concrete types, each carrying a stable
`code` and an HTTP `status`. Diagnostic context lives in a `detail` field that
`toResponse()` does not read, so internal information cannot reach a client by
accident.

**Primitives** — `generateId`, `generateToken`, `hashToken`, `safeEqual`, and
ISO-8601 time predicates that fail closed on unparseable input.

## Status

Pre-release (0.1.0). Not independently audited. See the
[security policy](https://github.com/NinshoORG/ninsho/blob/main/SECURITY.md).

MIT
