# =====================================================================
#  VaultShare — Dockerfile
#  Multi-stage build: minimal production image (~80MB).
#  Base: node:18-alpine
# =====================================================================

# ── STAGE 1: Dependencies ─────────────────────────────────────────────
FROM node:18-alpine AS deps

WORKDIR /app

# Copy package files only (leverages Docker layer caching)
COPY package*.json ./

# Install only production dependencies
RUN npm ci --omit=dev

# ── STAGE 2: Production Image ─────────────────────────────────────────
FROM node:18-alpine AS production

# Security: run as non-root user
RUN addgroup -g 1001 -S vaultshare && \
    adduser  -u 1001 -S vaultshare -G vaultshare

WORKDIR /app

# Copy production deps from stage 1
COPY --from=deps /app/node_modules ./node_modules

# Copy application files
COPY --chown=vaultshare:vaultshare server.js  ./
COPY --chown=vaultshare:vaultshare public/    ./public/
COPY --chown=vaultshare:vaultshare package.json ./

# Drop to non-root
USER vaultshare

# Expose application port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:3000/health || exit 1

# Set production environment
ENV NODE_ENV=production \
    PORT=3000

# Start server
CMD ["node", "server.js"]
