/** @type {import('next').NextConfig} */
const nextConfig = {
  // Tell Next.js we're behind a proxy
  poweredByHeader: false,
  // Configure how Next.js should handle the host header and protocol
  basePath: process.env.NODE_ENV === 'production' ? '' : '',
  assetPrefix: process.env.NODE_ENV === 'production' 
    ? 'https://zerodaybeta.betwixtai.com' 
    : '',
  // Trust the proxy's headers
  experimental: {
    forwardClientHeaders: true
  }
}

module.exports = nextConfig 