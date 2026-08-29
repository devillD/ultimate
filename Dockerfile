# Ultra-minimal production runtime using 0abir/minimum:node
FROM 0abir/minimum:node
WORKDIR /app

# Copy application source files
COPY bare ./bare
COPY static ./static
COPY package.json index.js index.mjs ./

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=:: \
    NODE_OPTIONS="--max-old-space-size=180"

EXPOSE 8080

CMD ["node", "index.js"]
