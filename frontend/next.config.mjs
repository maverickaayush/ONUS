/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // Match the previous frontend's Docker build behavior: a stray type error
  // must not fail the production image build (the app typechecks clean today).
  typescript: {
    ignoreBuildErrors: true,
  },
  // The circular badge that appeared bottom-left in every screenshot was the
  // Next.js dev-tools indicator (framework-injected, dev-only, never in prod and
  // never in this codebase) — not an account avatar. Disabled so the rail is
  // clean in dev too.
  devIndicators: false,
  images: {
    unoptimized: true,
  },
  async rewrites() {
    // Same-origin proxy: the browser only ever calls /api/* on this origin;
    // Next.js rewrites it server-side to the FastAPI backend. In Docker,
    // NEXT_INTERNAL_API_URL=http://backend:8000. Native dev falls back to
    // localhost:8000. Mirrors the existing frontend exactly and is what keeps
    // requests inside the backend's hardcoded CORS allowlist.
    const apiBase = process.env.NEXT_INTERNAL_API_URL || 'http://localhost:8000'
    return [
      {
        source: '/api/:path*',
        destination: `${apiBase}/api/:path*`,
      },
    ]
  },
}

export default nextConfig
