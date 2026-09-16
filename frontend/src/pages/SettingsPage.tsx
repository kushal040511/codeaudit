import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, FolderGit2 as Github, KeyRound, Lock, LogOut, ShieldCheck, Unplug } from 'lucide-react'
import { type FormEvent, useState } from 'react'
import { useSearchParams } from 'react-router'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  type ApiError,
  type ApiToken,
  type ApiTokenCreated,
  createApiToken,
  disconnectGitHub,
  githubLoginUrl,
  listApiTokens,
  logout,
  type Me,
  revokeApiToken,
} from '@/lib/api'
import { ME_QUERY_KEY, useAuthConfig, useMe } from '@/lib/auth'
import { formatDateTime } from '@/lib/format'

const OAUTH_ERRORS: Record<string, string> = {
  invalid_oauth_state: 'The sign-in request expired or did not start in this browser. Try again.',
  access_denied: 'You cancelled the GitHub authorization.',
  oauth_exchange_failed: 'GitHub did not accept the sign-in. Try again.',
  github_account_in_use: 'That GitHub account is already connected to another CodeAudit user.',
  github_unavailable: 'Could not reach GitHub. Try again later.',
  github_not_configured: 'GitHub sign-in is not configured on this server.',
}

const SCOPE_INFO: Record<string, string> = {
  'read:user': 'Read your public profile (name, avatar).',
  public_repo: 'Read public repositories and push branches / open pull requests on them, only when you confirm one.',
  repo: 'Full access to private repositories you can access: read code to scan it and, only when you confirm, push a branch and open a pull request.',
}

function ScopeList({ scopes }: { scopes: string[] }) {
  return (
    <ul className="space-y-1.5">
      {scopes.map((scope) => (
        <li key={scope} className="flex flex-wrap items-baseline gap-2 text-sm">
          <Badge variant="outline" className="font-mono">
            {scope}
          </Badge>
          <span className="text-muted-foreground">{SCOPE_INFO[scope] ?? 'Granted by GitHub.'}</span>
        </li>
      ))}
    </ul>
  )
}

function GitHubCard({ me, enabled }: { me: Me | null; enabled: boolean }) {
  const queryClient = useQueryClient()
  const [confirming, setConfirming] = useState(false)
  const disconnect = useMutation({
    mutationFn: disconnectGitHub,
    onSuccess: () => {
      setConfirming(false)
      void queryClient.invalidateQueries({ queryKey: ME_QUERY_KEY })
    },
  })
  const github = me?.github
  const connected = github?.connected ?? false

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Github aria-hidden className="size-5" /> GitHub
        </CardTitle>
        <CardDescription>
          Scan repositories by URL and open pull requests with verified fixes. CodeAudit never writes to a repository
          unless you review a preview and confirm it.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {!enabled ? (
          <p className="text-sm text-muted-foreground">
            GitHub integration isn't configured on this server (GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET and
            TOKEN_ENCRYPTION_KEYS). Public repositories can still be scanned by URL.
          </p>
        ) : connected && github ? (
          <>
            <div className="flex flex-wrap items-center gap-3">
              {me?.avatar_url && <img src={me.avatar_url} alt="" className="size-10 rounded-full border" />}
              <div>
                <div className="font-medium">{me?.display_name}</div>
                <a
                  href={`https://github.com/${github.login}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-sm text-muted-foreground hover:underline"
                >
                  @{github.login}
                </a>
              </div>
              <Badge className="ml-auto bg-emerald-600 text-white">
                <ShieldCheck aria-hidden /> Connected
              </Badge>
            </div>

            <div className="space-y-2">
              <h3 className="text-sm font-medium">Granted permissions</h3>
              <ScopeList scopes={github.scopes} />
              {github.token_expires_at && (
                <p className="text-xs text-muted-foreground">
                  Access token expires {formatDateTime(github.token_expires_at)}; it is refreshed automatically.
                </p>
              )}
            </div>

            {!github.private_repo_access && (
              <div className="rounded-lg border p-4 text-sm">
                <p className="flex items-center gap-2 font-medium">
                  <Lock aria-hidden className="size-4" /> Private repositories
                </p>
                <p className="mt-1 text-muted-foreground">
                  Scanning private repositories needs GitHub's <code className="font-mono">repo</code> scope. GitHub
                  has no read-only scope for private code, so it grants write access too. CodeAudit only uses it to
                  clone for scans and, when you confirm a preview, to open a pull request.
                </p>
                <Button asChild size="sm" variant="outline" className="mt-3">
                  <a href={githubLoginUrl({ privateRepos: true })}>Grant private repository access</a>
                </Button>
              </div>
            )}

            <div className="flex flex-wrap items-center gap-2 border-t pt-4">
              {confirming ? (
                <>
                  <span className="text-sm">
                    Revoke CodeAudit's access at GitHub and delete the stored token? Scans stay, but you can't open pull
                    requests until you reconnect.
                  </span>
                  <Button size="sm" variant="destructive" disabled={disconnect.isPending} onClick={() => disconnect.mutate()}>
                    {disconnect.isPending ? 'Disconnecting…' : 'Disconnect'}
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>
                    Cancel
                  </Button>
                </>
              ) : (
                <Button size="sm" variant="outline" onClick={() => setConfirming(true)}>
                  <Unplug aria-hidden /> Disconnect GitHub
                </Button>
              )}
            </div>
            {disconnect.isError && (
              <p role="alert" className="text-sm text-destructive">
                {(disconnect.error as ApiError).message}
              </p>
            )}
          </>
        ) : (
          <>
            {github && !github.connected && (
              <p className="text-sm text-muted-foreground">
                GitHub account @{github.login} is disconnected. Reconnect to scan private repositories or open pull
                requests.
              </p>
            )}
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-lg border p-4">
                <h3 className="font-medium">Public repositories</h3>
                <div className="mt-2">
                  <ScopeList scopes={['read:user', 'public_repo']} />
                </div>
                <Button asChild className="mt-4">
                  <a href={githubLoginUrl()}>
                    <Github aria-hidden /> Connect GitHub
                  </a>
                </Button>
              </div>
              <div className="rounded-lg border p-4">
                <h3 className="font-medium">Public and private repositories</h3>
                <div className="mt-2">
                  <ScopeList scopes={['read:user', 'repo']} />
                </div>
                <Button asChild variant="outline" className="mt-4">
                  <a href={githubLoginUrl({ privateRepos: true })}>
                    <Lock aria-hidden /> Connect with private access
                  </a>
                </Button>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function ApiTokensCard() {
  const queryClient = useQueryClient()
  const [name, setName] = useState('GitHub Action')
  const [created, setCreated] = useState<ApiTokenCreated | null>(null)
  const [copied, setCopied] = useState(false)
  const tokens = useQuery<ApiToken[], ApiError>({ queryKey: ['auth', 'tokens'], queryFn: listApiTokens })
  const create = useMutation<ApiTokenCreated, ApiError, string>({
    mutationFn: createApiToken,
    onSuccess: (token) => {
      setCreated(token)
      setCopied(false)
      void queryClient.invalidateQueries({ queryKey: ['auth', 'tokens'] })
    },
  })
  const revoke = useMutation<void, ApiError, number>({
    mutationFn: revokeApiToken,
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['auth', 'tokens'] }),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    if (name.trim()) create.mutate(name.trim())
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound aria-hidden className="size-5" /> API tokens
        </CardTitle>
        <CardDescription>
          For the CodeAudit GitHub Action and other automation. A token can create and read your scans. It can't open
          pull requests, manage tokens or disconnect GitHub: those need you signed in here.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={submit} className="flex flex-wrap gap-2">
          <label className="sr-only" htmlFor="token-name">
            Token name
          </label>
          <input
            id="token-name"
            value={name}
            maxLength={100}
            onChange={(event) => setName(event.target.value)}
            className="h-8 min-w-48 flex-1 rounded-lg border bg-background px-2.5 text-sm"
          />
          <Button type="submit" disabled={create.isPending || !name.trim()}>
            Create token
          </Button>
        </form>
        {create.isError && (
          <p role="alert" className="text-sm text-destructive">
            {create.error.message}
          </p>
        )}
        {created && (
          <div className="space-y-2 rounded-lg border border-emerald-300 bg-emerald-50/60 p-3 text-sm dark:border-emerald-900 dark:bg-emerald-950/30">
            <p className="font-medium">Copy this token now. It won't be shown again.</p>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded bg-background px-2 py-1 font-mono text-xs">
                {created.token}
              </code>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  void navigator.clipboard.writeText(created.token).then(() => setCopied(true))
                }}
              >
                {copied ? <Check aria-hidden /> : <Copy aria-hidden />} {copied ? 'Copied' : 'Copy'}
              </Button>
            </div>
          </div>
        )}
        {tokens.data && tokens.data.length > 0 && (
          <ul className="divide-y rounded-lg border text-sm">
            {tokens.data.map((token) => (
              <li key={token.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
                <span className="font-medium">{token.name}</span>
                <code className="font-mono text-xs text-muted-foreground">{token.prefix}…</code>
                <span className="text-xs text-muted-foreground">
                  created {formatDateTime(token.created_at)}
                  {token.last_used_at && ` · last used ${formatDateTime(token.last_used_at)}`}
                </span>
                {token.revoked_at ? (
                  <Badge variant="secondary" className="ml-auto">
                    Revoked
                  </Badge>
                ) : (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="ml-auto text-destructive"
                    disabled={revoke.isPending}
                    onClick={() => revoke.mutate(token.id)}
                  >
                    Revoke
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

export function SettingsPage() {
  const [params] = useSearchParams()
  const queryClient = useQueryClient()
  const me = useMe()
  const config = useAuthConfig()
  const signOut = useMutation({
    mutationFn: logout,
    onSuccess: () => queryClient.setQueryData(ME_QUERY_KEY, null),
  })
  const oauthError = params.get('github_error')

  if (me.isPending || config.isPending) return <p className="text-sm text-muted-foreground">Loading settings…</p>

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div className="flex items-center justify-between gap-4">
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        {me.data && (
          <Button variant="ghost" size="sm" onClick={() => signOut.mutate()} disabled={signOut.isPending}>
            <LogOut aria-hidden /> Sign out
          </Button>
        )}
      </div>
      {oauthError && (
        <p role="alert" className="rounded-lg border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive">
          {OAUTH_ERRORS[oauthError] ?? `GitHub sign-in failed (${oauthError}).`}
        </p>
      )}
      {me.isError && (
        <p role="alert" className="text-sm text-destructive">
          Could not load your account: {me.error.message}
        </p>
      )}
      <GitHubCard me={me.data ?? null} enabled={config.data?.github_enabled ?? false} />
      {me.data && <ApiTokensCard />}
    </div>
  )
}
