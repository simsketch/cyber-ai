import { UserButton } from "@clerk/nextjs"

export function UserNav() {
  return (
    <div className="flex items-center gap-4">
      <UserButton
        afterSignOutUrl="/"
        appearance={{
          elements: {
            avatarBox: "h-9 w-9",
          },
        }}
      />
    </div>
  )
} 