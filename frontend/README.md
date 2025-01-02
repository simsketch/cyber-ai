Based on the troubleshooting we did, there were several issues that combined to cause the problem:
Routing Configuration: Initially, we were using redirect('/dashboard') in the root page, which wasn't working reliably. We switched to using Next.js's built-in rewrites() configuration in next.config.js, which is a more robust way to handle root path redirection.
Missing Dependencies: We had several missing or incorrectly installed dependencies:
@nivo/network was missing
@radix-ui/react-checkbox was missing
There were peer dependency conflicts that we resolved using --legacy-peer-deps
Type Issues: There were TypeScript errors in the theme provider where we were trying to import ThemeProviderProps from next-themes which didn't exist. We fixed this by creating our own interface.
Caching: The .next directory and node_modules/.cache were causing issues with stale builds, which is why we had to repeatedly clean them using rm -rf .next node_modules/.cache.
If this happens again, here's the checklist to follow:
Clear the Next.js cache: rm -rf .next node_modules/.cache
Check package.json for any missing dependencies
Install dependencies with --legacy-peer-deps if there are version conflicts
Use rewrites() in next.config.js instead of client-side redirects for root path handling
Rebuild the application: npm run build
The most important lesson is that for root path redirection, using Next.js's built-in rewrites() configuration is more reliable than client-side redirects or middleware.

Ah, now I see the root cause! There were actually competing redirect mechanisms:
The middleware (middleware.ts) was trying to handle redirects using NextResponse.redirect
The root page (page.tsx) was trying to handle redirects using redirect()
And finally, we added a third mechanism with rewrites() in next.config.js
The starter page kept showing up because:
When Next.js initializes, it first serves the default page content before any client-side redirects can take effect
The middleware redirect and the page redirect were potentially conflicting with each other
The default Next.js starter page is part of the default template and gets served momentarily before any redirects can take effect
The solution that finally worked was using rewrites() in next.config.js because:
It happens at the routing level, before any page content is served
It's more performant as it doesn't involve an actual redirect - it just internally maps / to /dashboard
It avoids the race condition between middleware redirects and page redirects
To prevent this in the future:
Use only one redirect mechanism (preferably rewrites() for root path handling)
Remove any competing redirect logic from middleware or page components
Clear the .next cache when making routing changes to ensure old routing rules aren't persisted
This is why we saw the starter page - it was being momentarily rendered before the various redirect mechanisms could take effect, creating a flash of unwanted content.