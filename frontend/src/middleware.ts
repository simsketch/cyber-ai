import { authMiddleware } from "@clerk/nextjs";
import { NextResponse } from "next/server";

// Debug middleware to log auth information
export default authMiddleware({
  publicRoutes: ["/", "/sign-in", "/sign-up"],
  beforeAuth: (req) => {
    // Force HTTPS in production and fix domain
    if (process.env.NODE_ENV === 'production') {
      const protocol = req.headers.get('x-forwarded-proto') || 'http';
      const host = req.headers.get('host') || 'zerodaybeta.betwixtai.com';
      
      // Create a new URL with the correct protocol and host
      const url = new URL(req.nextUrl.pathname + req.nextUrl.search, `https://${host}`);
      
      // Force HTTPS redirect if needed
      if (protocol !== 'https') {
        console.log('[Auth Debug] Redirecting to:', url.toString());
        return NextResponse.redirect(url);
      }

      // Rewrite the URL to use HTTPS and the correct domain
      console.log('[Auth Debug] Rewriting URL to:', url.toString());
      return NextResponse.rewrite(url);
    }

    console.log('\n[Auth Debug] ---- New Request ----');
    console.log('[Auth Debug] Request URL:', req.url);
    console.log('[Auth Debug] NextURL:', req.nextUrl.toString());
    console.log('[Auth Debug] Method:', req.method);
    console.log('[Auth Debug] Host:', req.headers.get('host'));
    console.log('[Auth Debug] Origin:', req.headers.get('origin'));
    console.log('[Auth Debug] Referer:', req.headers.get('referer'));
    console.log('[Auth Debug] Auth Header:', req.headers.get('authorization'));
    console.log('[Auth Debug] Cookie Header:', req.headers.get('cookie'));
    
    // Log security-related headers
    console.log('[Auth Debug] Security Headers:', {
      'x-forwarded-proto': req.headers.get('x-forwarded-proto'),
      'x-forwarded-host': req.headers.get('x-forwarded-host'),
      'x-real-ip': req.headers.get('x-real-ip'),
    });
    
    return null;
  },
  afterAuth: (auth, req) => {
    console.log('[Auth Debug] Auth State:', {
      userId: auth.userId,
      sessionId: auth.sessionId,
      isPublicRoute: auth.isPublicRoute,
      isApiRoute: auth.isApiRoute,
      orgId: auth.orgId,
    });
    if (!auth.userId && !auth.isPublicRoute) {
      console.log('[Auth Debug] Auth failed - Protected route access attempted without auth');
      console.log('[Auth Debug] Request origin:', req.headers.get('origin'));
      console.log('[Auth Debug] Request host:', req.headers.get('host'));
    }
    return null;
  },
  debug: true,
});

export const config = {
  matcher: ["/((?!.+\\.[\\w]+$|_next).*)", "/", "/(api|trpc)(.*)"],
}; 