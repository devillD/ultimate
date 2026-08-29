# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM 0abir/minimum:node AS build
WORKDIR /app/src
COPY . .
ENV INPUT_DIR=/app/src
ENV OUTPUT_DIR=/app/src
RUN /opt/minimum/scripts/run.sh

# Stage 2: Minimal production runtime
FROM gcr.io/distroless/nodejs24-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /app/src /app
ENV NODE_ENV=production \
    PORT=8080 \
    HOST=:: \
    NODE_OPTIONS="--max-old-space-size=180"
USER nonroot
EXPOSE 8080
CMD ["index.js"]