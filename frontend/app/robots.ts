import type { MetadataRoute } from 'next'

// Auth-gated operator console: keep the app routes out of search indexes.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: '*', disallow: ['/scan/', '/scans', '/sign-in', '/sign-up'] },
  }
}
