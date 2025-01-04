/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return {
      beforeFiles: [
        // Handle all Auth0 routes
        {
          source: '/api/auth/login',
          destination: '/api/auth/[auth0]/login',
        },
        {
          source: '/api/auth/logout',
          destination: '/api/auth/[auth0]/logout',
        },
        {
          source: '/api/auth/callback',
          destination: '/api/auth/[auth0]/callback',
        },
        {
          source: '/api/auth/me',
          destination: '/api/auth/[auth0]/me',
        },
      ],
    }
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'Access-Control-Allow-Credentials',
            value: 'true',
          },
          {
            key: 'Access-Control-Allow-Origin',
            value: '*',
          },
          {
            key: 'Access-Control-Allow-Methods',
            value: 'GET,DELETE,PATCH,POST,PUT,OPTIONS',
          },
          {
            key: 'Access-Control-Allow-Headers',
            value: 'Accept,Authorization,Content-Type,X-Requested-With',
          },
        ],
      },
    ]
  },
}

module.exports = nextConfig 