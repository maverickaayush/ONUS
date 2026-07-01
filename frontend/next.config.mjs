/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    // In Docker, NEXT_INTERNAL_API_URL=http://backend:8000 (compose service
    // name). In native dev it's unset, falling back to localhost:8000.
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
