import { authMiddleware } from "@clerk/nextjs";
import { NextResponse } from "next/server";

// Debug middleware to log auth information
export default authMiddleware({
  debug: true,
  publicRoutes: ["/", "/sign-in", "/sign-up"],
  beforeAuth: (req) => {
    console.log('\n[Auth Debug] ---- New Request ----');
    console.log('[Auth Debug] Request URL:', req.url);
    console.log('[Auth Debug] NextURL:', req.nextUrl.toString());
    console.log('[Auth Debug] Host:', req.headers.get('host'));
    console.log('[Auth Debug] Origin:', req.headers.get('origin'));
    console.log('[Auth Debug] Referer:', req.headers.get('referer'));
    
    // Log security-related headers
    console.log('[Auth Debug] Security Headers:', {
      'x-forwarded-proto': req.headers.get('x-forwarded-proto'),
      'x-forwarded-host': req.headers.get('x-forwarded-host'),
    });
    
    return null;
  },
  afterAuth: (auth, req) => {
    console.log('[Auth Debug] Auth State:', {
      userId: auth.userId,
      sessionId: auth.sessionId,
      isPublicRoute: auth.isPublicRoute,
      isApiRoute: auth.isApiRoute,
    });
    return null;
  },
  ...(process.env.NODE_ENV === 'production' ? {
    authorizedParties: ["https://zerodaybeta.betwixtai.com"],
  } : {}),
});

export const config = {
  matcher: ["/((?!.+\\.[\\w]+$|_next).*)", "/", "/(api|trpc)(.*)"],
}; 