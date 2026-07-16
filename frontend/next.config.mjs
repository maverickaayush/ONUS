/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // Production build enforces types (the app typechecks clean). A regression
  // that introduces a type error should fail the build, not ship silently.
  typescript: {
    ignoreBuildErrors: false,
  },
  // The circular badge that appeared bottom-left in every screenshot was the
  // Next.js dev-tools indicator (framework-injected, dev-only, never in prod and
  // never in this codebase) — not an account avatar. Disabled so the rail is
  // clean in dev too.
  devIndicators: false,
  images: {
    unoptimized: true,
  },
  async headers() {
    // Safe baseline security headers for an auth-bearing app. (No strict CSP:
    // the UI relies on inline styles; a nonce-based CSP is a separate, larger
    // change — noted in the audit, not shipped half-done.)
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ]
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
