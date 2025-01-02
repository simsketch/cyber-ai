export function Footer() {
  return (
    <footer className="border-t py-6 md:py-0">
      <div className="container flex flex-col items-center justify-between gap-4 md:h-16 md:flex-row">
        <p className="text-sm text-muted-foreground">
          © 2024 Betwixt. All rights reserved.
        </p>
        <div className="flex items-center gap-4">
          <a
            href="https://github.com/betwixt-labs"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted-foreground hover:text-foreground"
          >
            GitHub
          </a>
          <a
            href="https://betwixt.dev"
            target="_blank"
            rel="noopener noreferrer"
            className="text-sm text-muted-foreground hover:text-foreground"
          >
            Website
          </a>
        </div>
      </div>
    </footer>
  )
} 