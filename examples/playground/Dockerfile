# The playground, packaged for a public host.
#
# Built from the repository root so the workspace packages the demo runs are
# the ones in this checkout, not published copies:
#
#     docker build -f examples/playground/Dockerfile -t ninsho-playground .
#
# ─── What this image is, and is not ────────────────────────────────────────
# It serves a demonstration that hands out internals over HTTP on purpose: the
# live keyspace, the store operations behind each request, the audit trail.
# That is the point of the page and the reason it must never share a host, a
# network, or a Redis with anything real. It keeps no data of its own — every
# visitor gets an in-memory world that is swept when they go idle.
# ───────────────────────────────────────────────────────────────────────────

FROM node:24-alpine AS build
WORKDIR /app

# Lockfile first, so a dependency change is what invalidates the layer rather
# than a source edit.
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/server/package.json packages/server/
COPY packages/webauthn/package.json packages/webauthn/
COPY packages/client/package.json packages/client/
COPY examples/playground/package.json examples/playground/

# `npm ci` refuses a lockfile that disagrees with the manifests, which is the
# same regression gate CI runs on.
RUN npm ci --workspace @ninshorg/playground --include-workspace-root

# The shared compiler configuration every package extends. Without it tsup's
# declaration build cannot resolve the base config and fails.
COPY tsconfig.base.json ./

COPY packages/ packages/
COPY examples/playground/ examples/playground/

RUN npm run build --workspace @ninshorg/core \
 && npm run build --workspace @ninshorg/server \
 && npm run build --workspace @ninshorg/webauthn \
 && npm run build --workspace @ninshorg/client

# ─── Runtime ───────────────────────────────────────────────────────────────
FROM node:24-alpine
WORKDIR /app

# ─── Deliberately not `production`, and this is the interesting line ───────
# `MemoryStore` refuses to construct when NODE_ENV is `production`, because
# session state that is per-process and lost on restart would silently break
# revocation and rate limiting in a real deployment. There is no override flag:
# the store's own documentation says a deployment that genuinely wants
# in-memory sessions should implement `NinshoStore` itself, and that defeating
# the guard by unsetting NODE_ENV must be a deliberate act.
#
# This is that deliberate act, named rather than omitted. The playground *is*
# the demonstration: every visitor gets a throwaway world that is supposed to
# vanish, and a restart losing all of them is the intended behaviour rather
# than an outage. Anyone copying this file for something real should set
# `NODE_ENV=production` and watch it refuse to start — which is the guard doing
# its job.
ENV NODE_ENV=demonstration
ENV PORT=4000

# `node` is a non-root user the base image already provides. The process reads
# its own files and binds a port; it has no reason to be able to do more.
COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/packages ./packages
COPY --from=build --chown=node:node /app/examples/playground ./examples/playground

USER node
EXPOSE 4000

# The demo answers /health without touching a visitor's world, so a probe does
# not create one.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["npm", "run", "start", "--workspace", "@ninshorg/playground"]
