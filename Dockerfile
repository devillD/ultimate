# ── Stage 1: Builder ─────────────────────────────────────────────────────────
# Uses 0abir/minimum:node to prepare production-ready application files
FROM 0abir/minimum:node AS builder
WORKDIR /app

COPY package.json ./
COPY bare ./bare
COPY static ./static
COPY index.js index.mjs ./

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
# Distroless non-root runtime — no shell, no package manager, minimal attack surface
FROM gcr.io/distroless/nodejs24-debian12:nonroot
WORKDIR /app

# Copy only production artifacts from builder
COPY --from=builder --chown=nonroot:nonroot /app/bare ./bare
COPY --from=builder --chown=nonroot:nonroot /app/static ./static
COPY --from=builder --chown=nonroot:nonroot /app/package.json /app/index.js /app/index.mjs ./

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=:: \
    NODE_OPTIONS="--max-old-space-size=180"

USER nonroot
EXPOSE 8080

CMD ["index.js"]
