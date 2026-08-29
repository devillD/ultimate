# Minimal Distroless production runtime (<45MB) with 0 external runtime dependencies
FROM gcr.io/distroless/nodejs24-debian12:nonroot
WORKDIR /app

# Copy application source files
COPY --chown=nonroot:nonroot bare ./bare
COPY --chown=nonroot:nonroot static ./static
COPY --chown=nonroot:nonroot package.json index.js index.mjs ./

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=:: \
    NODE_OPTIONS="--max-old-space-size=180"

USER nonroot
EXPOSE 8080

CMD ["index.js"]
