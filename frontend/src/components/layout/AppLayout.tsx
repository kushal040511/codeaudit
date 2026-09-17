import { Link, NavLink, Outlet } from 'react-router'
import { BlueprintBackground } from '@/components/layout/BlueprintBackground'
import { githubLoginUrl } from '@/lib/api'
import { useAuthConfig, useMe } from '@/lib/auth'
import { cn } from '@/lib/utils'

const navItems = [
  { to: '/', label: 'Home', end: true, desktopOnly: true },
  { to: '/upload', label: 'Scan code', end: false },
  { to: '/sites', label: 'Site Analyzer', end: false },
  { to: '/settings', label: 'Settings', end: false },
]

function Mark() {
  // Three modules and their imports: the graph motif in miniature.
  return (
    <svg viewBox="0 0 28 28" aria-hidden className="size-7">
      <path d="M7 7 L21 11 M7 7 L10 21 M21 11 L10 21" stroke="var(--graphite)" strokeWidth="1.5" fill="none" />
      <rect x="4" y="4" width="6" height="6" fill="var(--ink)" />
      <rect x="18" y="8" width="6" height="6" fill="var(--blueprint)" />
      <rect x="7" y="18" width="6" height="6" fill="var(--ink)" />
      <ellipse cx="21" cy="11" rx="6.5" ry="5.5" transform="rotate(-18 21 11)" stroke="var(--pencil)" strokeWidth="1.3" fill="none" />
    </svg>
  )
}

function Account() {
  const me = useMe()
  const config = useAuthConfig()
  if (me.isPending) return null
  if (me.data) {
    return (
      <Link to="/settings" className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground">
        {me.data.avatar_url && <img src={me.data.avatar_url} alt="" className="size-6 rounded-full border" />}
        <span className="hidden sm:inline">{me.data.github?.login ?? me.data.display_name}</span>
      </Link>
    )
  }
  if (!config.data?.github_enabled) return null
  return (
    <a href={githubLoginUrl({ next: window.location.pathname })} className="text-sm font-medium text-primary hover:underline">
      Sign in with GitHub
    </a>
  )
}

export function AppLayout() {
  return (
    <div className="relative min-h-svh text-foreground">
      <BlueprintBackground />
      <a
        href="#main"
        className="sr-only z-50 rounded bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
      >
        Skip to content
      </a>
      <header className="sticky top-0 z-20 border-b border-border/70 bg-[color-mix(in_oklab,var(--vellum)_78%,transparent)] backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-6xl items-center gap-3 px-4 sm:gap-8">
          <Link to="/" className="flex items-center gap-2.5" data-no-pulse>
            <Mark />
            <span className="hidden font-heading text-xl font-semibold [font-stretch:72%] sm:inline">CodeAudit</span>
          </Link>
          <nav className="flex min-w-0 gap-0.5 overflow-x-auto text-sm sm:gap-1" aria-label="Main">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn(
                    'group relative rounded px-2.5 py-2 whitespace-nowrap text-muted-foreground transition-colors hover:text-foreground sm:px-3',
                    isActive && 'text-foreground',
                    item.desktopOnly && 'hidden sm:block',
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    {item.label}
                    {/* The active page is underlined in pencil; the stroke draws in when you navigate. */}
                    <svg
                      aria-hidden
                      viewBox="0 0 100 8"
                      preserveAspectRatio="none"
                      className="pointer-events-none absolute inset-x-2 -bottom-0.5 h-2 w-[calc(100%-1rem)]"
                    >
                      <path
                        d="M2 5 C 25 2, 55 7, 98 3"
                        fill="none"
                        stroke="var(--pencil)"
                        strokeWidth="2.2"
                        strokeLinecap="round"
                        pathLength={1}
                        className={cn(
                          'transition-[stroke-dashoffset] duration-500 ease-out [stroke-dasharray:1]',
                          isActive ? '[stroke-dashoffset:0]' : '[stroke-dashoffset:1] group-hover:[stroke-dashoffset:0.7]',
                        )}
                      />
                    </svg>
                  </>
                )}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto">
            <Account />
          </div>
        </div>
      </header>
      <main id="main" className="relative z-10 mx-auto max-w-6xl px-4 py-10">
        <Outlet />
      </main>
    </div>
  )
}
