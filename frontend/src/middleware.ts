import { authMiddleware } from "@clerk/nextjs";

// Debug middleware to log auth information
export default authMiddleware({
  publicRoutes: ["/", "/sign-in", "/sign-up"],
  beforeAuth: (req) => {
    console.log('\n[Auth Debug] ---- New Request ----');
    console.log('[Auth Debug] Request URL:', req.url);
    console.log('[Auth Debug] Method:', req.method);
    console.log('[Auth Debug] Auth Header:', req.headers.get('authorization'));
    console.log('[Auth Debug] Cookie Header:', req.headers.get('cookie'));
    console.log('[Auth Debug] All Headers:', Object.fromEntries(req.headers.entries()));
    return null;
  },
  afterAuth: (auth, req) => {
    console.log('[Auth Debug] Auth State:', {
      userId: auth.userId,
      sessionId: auth.sessionId,
      sessionClaims: auth.sessionClaims,
      isPublicRoute: auth.isPublicRoute,
      isApiRoute: auth.isApiRoute,
    });
    if (!auth.userId && !auth.isPublicRoute) {
      console.log('[Auth Debug] Auth failed - Protected route access attempted without auth');
    }
    return null;
  },
});

export const config = {
  matcher: ["/((?!.+\\.[\\w]+$|_next).*)", "/", "/(api|trpc)(.*)"],
}; 