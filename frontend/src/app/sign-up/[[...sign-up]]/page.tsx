import { SignUp } from "@clerk/nextjs"

export default function SignUpPage() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <SignUp appearance={{
        elements: {
          card: "bg-background",
          formButtonPrimary: "bg-primary text-primary-foreground hover:bg-primary/90",
        }
      }} />
    </div>
  )
} 