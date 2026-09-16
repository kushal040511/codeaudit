import { Link, NavLink, Outlet } from 'react-router'
import { githubLoginUrl } from '@/lib/api'
import { useAuthConfig, useMe } from '@/lib/auth'
import { cn } from '@/lib/utils'

const navItems = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/upload', label: 'New scan', end: false },
  { to: '/settings', label: 'Settings', end: false },
]

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
    <a href={githubLoginUrl({ next: window.location.pathname })} className="text-sm underline-offset-4 hover:underline">
      Sign in with GitHub
    </a>
  )
}

export function AppLayout() {
  return (
    <div className="min-h-svh bg-background text-foreground">
      <header className="border-b">
        <div className="mx-auto flex h-14 max-w-6xl items-center gap-6 px-4">
          <span className="font-semibold tracking-tight">CodeAudit</span>
          <nav className="flex gap-4 text-sm">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn('text-muted-foreground hover:text-foreground', isActive && 'text-foreground')
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto">
            <Account />
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-8">
        <Outlet />
      </main>
    </div>
  )
}
