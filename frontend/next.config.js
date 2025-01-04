/** @type {import('next').NextConfig} */
const nextConfig = {
  // Tell Next.js we're behind a proxy
  poweredByHeader: false,
  env: {
    NEXT_PUBLIC_URL: process.env.NODE_ENV === 'production' 
      ? 'https://zerodaybeta.betwixtai.com' 
      : 'http://localhost:3000'
  },
  // Configure how Next.js should handle the host header and protocol
  assetPrefix: process.env.NODE_ENV === 'production' 
    ? 'https://zerodaybeta.betwixtai.com' 
    : '',
  // Trust the proxy's headers
  serverRuntimeConfig: {
    trustProxy: true
  },
  // Override the hostname and protocol in production
  experimental: {
    trustHostHeader: true,
  }
}

module.exports = nextConfig 