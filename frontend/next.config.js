/** @type {import('next').NextConfig} */
const nextConfig = {
  headers: async () => {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-Forwarded-Proto',
            value: 'https'
          }
        ]
      }
    ]
  },
  // Tell Next.js we're behind a proxy
  poweredByHeader: false,
  env: {
    NEXT_PUBLIC_URL: process.env.NODE_ENV === 'production' 
      ? 'https://zerodaybeta.betwixtai.com' 
      : 'http://localhost:3000'
  }
}

module.exports = nextConfig 