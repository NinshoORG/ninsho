# Ninsho documentation

Reference material for building on Ninsho. Everything here is written against
the code in this repository; where a page names a default, an option or a test,
it was read from the source rather than remembered.

## Start here

| | |
| --- | --- |
| **[Getting started](./getting-started.md)** | From a clone to a working sign-in route. The shape of an integration, and the three decisions you have to make. |
| **[Configuration](./configuration.md)** | Every `NinshoConfig` option, its default, and what changing it costs you. |
| **[Authorization](./authorization.md)** | The guards — roles, scopes, ownership, tenancy, step-up — and how each one fails. |
| **[Framework adapters](./frameworks.md)** | Express, Fastify, Hono and Koa, none of which the library imports. |
| **[Architecture](./architecture.md)** | How the pieces fit: engines, stores, the request path, and the one read per request. |
| **[Deployment](./deployment.md)** | The checklist for putting this in front of real users. |

## Elsewhere in the repository

| | |
| --- | --- |
| [`README.md`](../README.md) | What works today, with the test behind each claim |
| [`SECURITY.md`](../SECURITY.md) | Threat model, and the limitations stated plainly |
| [`PERFORMANCE.md`](../PERFORMANCE.md) | Benchmarks, and what they say about the architecture |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | The rule, the setup, and the settled design constraints |
| [`AGENTS.md`](../AGENTS.md) | Orientation for an agent or a new contributor — repository map, commands, invariants, traps |
| [`CHANGELOG.md`](../CHANGELOG.md) | What changed, and what each change was found by |

## Package documentation

| Package | |
| --- | --- |
| [`@ninshorg/core`](../packages/core) | Types, errors, crypto helpers. Zero runtime dependencies |
| [`@ninshorg/server`](../packages/server) | The engine. `ioredis` only — no framework dependency |
| [`@ninshorg/webauthn`](../packages/webauthn) | Passkeys: what is verified, and what deliberately is not |
| [`@ninshorg/client`](../packages/client) | Browser DPoP client. Zero dependencies |

## Examples

| | |
| --- | --- |
| [`examples/express-api`](../examples/express-api) | A complete integration meant to be copied |
| [`examples/playground`](../examples/playground) | The interactive demonstration — ten panels, running the real library |

## A note on how to read this

This project has one rule: **a security property stated in the documentation
must name the test that demonstrates it.** So where a page here says something
is refused, prevented or guaranteed, it names a file. Those names are checkable,
and checking them is encouraged — running

```bash
cd packages/server && npx vitest run -t "requireOwner"
```

takes a few seconds and is a better answer than trusting a paragraph.

Where something is **not** guaranteed, the page says so rather than staying
quiet. [`SECURITY.md`](../SECURITY.md) collects those in one place.
