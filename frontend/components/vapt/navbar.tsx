"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"

function ShieldIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  )
}

const NAV_ITEMS = [
  { label: "New Scan", href: "/" },
  { label: "Scans", href: "/scans" },
  { label: "Scan Status", href: "/scan/demo/status" },
  { label: "Report", href: "/scan/demo/report" },
]

export function Navbar() {
  const pathname = usePathname()

  const isActive = (href: string) => {
    if (href === "/") return pathname === "/"
    // "/scans" has no "demo" substring, so the fallback formula below would
    // reduce to pathname.startsWith("/scan") - which *would* match a real
    // /scan/{id}/status or /scan/{id}/report page and wrongly highlight
    // this pill too. Needs its own exact-match branch (the two placeholder
    // hrefs below never matched anything anyway - this doesn't change that).
    if (href === "/scans") return pathname === "/scans"
    return pathname.startsWith(href.replace("demo", "").slice(0, -1))
  }

  return (
    <header className="sticky top-0 z-50 backdrop-blur-md bg-[#0a0e1a]/80 border-b border-white/8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          {/* Brand */}
          <Link href="/" className="flex items-center gap-2.5 group">
            <ShieldIcon
              className="h-6 w-6 text-blue-400 group-hover:text-blue-300 transition-colors"
              aria-hidden="true"
            />
            <div className="flex flex-col leading-none">
              <span className="text-slate-100 font-semibold text-sm tracking-tight">
                IIT Kanpur Computer Centre
              </span>
              <span className="text-slate-500 text-[10px] font-medium tracking-widest uppercase">
                VAPT Tool
              </span>
            </div>
          </Link>

          {/* Nav links */}
          <nav className="flex items-center gap-1" aria-label="Primary navigation">
            {NAV_ITEMS.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "px-3 py-1.5 rounded-lg text-sm font-medium transition-all duration-200",
                  isActive(item.href)
                    ? "bg-white/10 text-slate-100 border border-white/10"
                    : "text-slate-400 hover:text-slate-200 hover:bg-white/5",
                )}
              >
                {item.label}
              </Link>
            ))}
          </nav>
        </div>
      </div>
    </header>
  )
}
