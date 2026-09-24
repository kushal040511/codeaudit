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
      <path d="M7 7 L21 11 M7 7 L10 21 M21 11 L10 21" stroke="var(--mist)" strokeWidth="1.5" fill="none" />
      <rect x="4" y="4" width="6" height="6" fill="var(--haze)" />
      <rect x="18" y="8" width="6" height="6" fill="var(--haze)" />
      <rect x="7" y="18" width="6" height="6" fill="var(--flare)" />
    </svg>
  )
}

function Account() {
  const me = useMe()
  const config = useAuthConfig()
  if (me.isPending) return null
  if (me.data) {
    return (
      <Link to="/settings" className="flex items-center gap-2 text-sm text-mist hover:text-white">
        {me.data.avatar_url && (
          <img src={me.data.avatar_url} alt="" className="size-6 rounded-full border border-white/20" />
        )}
        <span className="hidden sm:inline">{me.data.github?.login ?? me.data.display_name}</span>
      </Link>
    )
  }
  if (!config.data?.github_enabled) return null
  return (
    <a
      href={githubLoginUrl({ next: window.location.pathname })}
      className="text-sm font-medium text-haze underline-offset-4 hover:text-white hover:underline"
    >
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
        className="sr-only z-50 bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:top-3 focus:left-3"
      >
        Skip to content
      </a>
      <header className="sticky top-0 z-20 bg-navy-deep text-white">
        <div className="mx-auto flex h-16 max-w-[1600px] items-center gap-3 px-[clamp(1rem,4vw,5rem)] sm:gap-10">
          <Link to="/" className="flex items-center gap-2.5" data-no-pulse>
            <Mark />
            <span className="hidden font-heading text-lg font-semibold tracking-tight sm:inline">CodeAudit</span>
          </Link>
          <nav className="flex min-w-0 gap-1 overflow-x-auto text-sm sm:gap-2" aria-label="Main">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn(
                    'relative px-2.5 py-2 whitespace-nowrap text-mist transition-colors hover:text-white sm:px-3',
                    isActive && 'text-white',
                    item.desktopOnly && 'hidden sm:block',
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    {item.label}
                    <span
                      aria-hidden
                      className={cn(
                        'pointer-events-none absolute inset-x-2.5 bottom-1 h-px origin-left bg-haze transition-transform duration-300 ease-instrument sm:inset-x-3',
                        isActive ? 'scale-x-100' : 'scale-x-0',
                      )}
                    />
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
      <main id="main" className="relative z-10 mx-auto max-w-[1600px] px-[clamp(1rem,4vw,5rem)] py-10">
        <Outlet />
      </main>
    </div>
  )
}
