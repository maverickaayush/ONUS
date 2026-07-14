# NOTE: this project's lockfile is package-lock.json (npm), not
# pnpm-lock.yaml — verified by inspection, not assumed. A pnpm build with
# --frozen-lockfile would fail immediately since no pnpm lockfile exists.
# Pulled from AWS's public ECR mirror of Docker Hub official images to avoid
# Docker Hub's anonymous pull rate limit failing CI builds (identical image).
FROM public.ecr.aws/docker/library/node:20-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# next.config.mjs's rewrites() is evaluated ONCE at `next build` time and
# baked into routes-manifest.json — NOT re-evaluated per-request at runtime,
# even with output: 'standalone' (verified: a runtime-only `environment:` in
# docker-compose.yml was silently ignored, proxy kept hitting localhost:8000
# from inside the container). So the backend URL must be supplied as a build
# ARG, present while `npm run build` actually runs.
ARG NEXT_INTERNAL_API_URL=http://backend:8000
ENV NEXT_INTERNAL_API_URL=$NEXT_INTERNAL_API_URL
RUN npm run build

FROM public.ecr.aws/docker/library/node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]
