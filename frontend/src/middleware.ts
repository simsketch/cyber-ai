import { authMiddleware } from "@clerk/nextjs";

// Debug middleware to log auth information
export default authMiddleware({
  publicRoutes: ["/", "/sign-in", "/sign-up"],
  beforeAuth: (req) => {
    console.log('[Auth Debug] Request URL:', req.url);
    console.log('[Auth Debug] Headers:', JSON.stringify(req.headers, null, 2));
    return null;
  },
  afterAuth: (auth, req) => {
    console.log('[Auth Debug] User authenticated:', !!auth.userId);
    console.log('[Auth Debug] Session:', !!auth.sessionId);
    if (!auth.userId) {
      console.log('[Auth Debug] Auth failed - no user ID');
    }
    return null;
  },
});

export const config = {
  matcher: ["/((?!.+\\.[\\w]+$|_next).*)", "/", "/(api|trpc)(.*)"],
}; 