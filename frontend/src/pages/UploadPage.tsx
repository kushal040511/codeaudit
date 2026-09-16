import { useMutation, useQuery } from '@tanstack/react-query'
import { CloudUpload, FileArchive, Lock } from 'lucide-react'
import { type DragEvent, type FormEvent, useId, useState } from 'react'
import { useNavigate } from 'react-router'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  type ApiError,
  createRepoScan,
  type GitHubRepo,
  githubLoginUrl,
  listGitHubRepos,
  type ScanCreated,
  uploadScan,
} from '@/lib/api'
import { useAuthConfig, useMe } from '@/lib/auth'
import { formatBytes } from '@/lib/format'
import { cn } from '@/lib/utils'

const MAX_UPLOAD_MB = 50

function validateFile(file: File): string | null {
  if (!file.name.toLowerCase().endsWith('.zip')) return 'Only .zip archives are accepted.'
  if (file.size === 0) return 'The selected file is empty.'
  if (file.size > MAX_UPLOAD_MB * 1024 * 1024) return `The archive exceeds the ${MAX_UPLOAD_MB} MB limit.`
  return null
}

function ZipUpload() {
  const inputId = useId()
  const navigate = useNavigate()
  const [dragActive, setDragActive] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [clientError, setClientError] = useState<string | null>(null)
  const [progress, setProgress] = useState(0)

  const upload = useMutation<ScanCreated, ApiError, File>({
    mutationFn: (selected) => uploadScan(selected, setProgress),
    onSuccess: ({ scan_id }) => navigate(`/scans/${scan_id}`),
  })

  function start(selected: File | undefined) {
    if (!selected || upload.isPending) return
    const error = validateFile(selected)
    setFile(selected)
    setClientError(error)
    setProgress(0)
    upload.reset()
    if (!error) upload.mutate(selected)
  }

  function onDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault()
    setDragActive(false)
    start(event.dataTransfer.files[0])
  }

  const errorMessage = clientError ?? upload.error?.message
  const percent = Math.round(progress * 100)

  return (
    <div className="space-y-4">
        <label
          htmlFor={inputId}
          onDragOver={(event) => {
            event.preventDefault()
            setDragActive(true)
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={onDrop}
          className={cn(
            'flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-10 text-center transition-colors',
            dragActive ? 'border-primary bg-muted' : 'border-muted-foreground/25 hover:bg-muted/50',
            upload.isPending && 'pointer-events-none opacity-60',
          )}
        >
          <CloudUpload aria-hidden className="size-8 text-muted-foreground" />
          <span className="font-medium">Drop a .zip here, or click to browse</span>
          <span className="text-sm text-muted-foreground">Up to {MAX_UPLOAD_MB} MB and 10,000 files</span>
        </label>
        <input
          id={inputId}
          type="file"
          accept=".zip,application/zip"
          className="sr-only"
          disabled={upload.isPending}
          onChange={(event) => {
            start(event.target.files?.[0])
            event.target.value = ''
          }}
        />

        {file && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm">
              <FileArchive aria-hidden className="size-4 shrink-0" />
              <span className="truncate">{file.name}</span>
              <span className="ml-auto shrink-0 text-muted-foreground">{formatBytes(file.size)}</span>
            </div>
            {upload.isPending && (
              <>
                <Progress value={percent} aria-label="Upload progress" />
                <p className="text-xs text-muted-foreground" aria-live="polite">
                  {progress < 1 ? `Uploading… ${percent}%` : 'Upload complete. Validating archive…'}
                </p>
              </>
            )}
          </div>
        )}

        {errorMessage && (
          <p role="alert" className="text-sm text-destructive">
            {errorMessage}
          </p>
        )}
    </div>
  )
}

function RepoScan() {
  const navigate = useNavigate()
  const me = useMe()
  const config = useAuthConfig()
  const [url, setUrl] = useState('')
  const [ref, setRef] = useState('')
  const [filter, setFilter] = useState('')
  const connected = me.data?.github?.connected ?? false
  const privateAccess = me.data?.github?.private_repo_access ?? false

  const repos = useQuery<GitHubRepo[], ApiError>({
    queryKey: ['github', 'repos'],
    queryFn: () => listGitHubRepos(),
    enabled: connected,
    staleTime: 60_000,
  })
  const scan = useMutation<ScanCreated, ApiError, { url: string; ref: string }>({
    mutationFn: ({ url, ref }) => createRepoScan(url.trim(), ref.trim() || undefined),
    onSuccess: ({ scan_id }) => navigate(`/scans/${scan_id}`),
  })

  function submit(event: FormEvent) {
    event.preventDefault()
    if (url.trim() && !scan.isPending) scan.mutate({ url, ref })
  }

  const visible = (repos.data ?? []).filter((repo) => repo.full_name.toLowerCase().includes(filter.toLowerCase()))

  return (
    <div className="space-y-5">
      <form onSubmit={submit} className="space-y-3">
        <div className="space-y-1.5">
          <label htmlFor="repo-url" className="text-sm font-medium">
            Repository URL
          </label>
          <input
            id="repo-url"
            required
            placeholder="https://github.com/owner/repo"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            className="h-9 w-full rounded-lg border bg-background px-3 font-mono text-sm"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <div className="space-y-1.5">
          <label htmlFor="repo-ref" className="text-sm font-medium">
            Branch, tag or commit <span className="font-normal text-muted-foreground">(optional)</span>
          </label>
          <input
            id="repo-ref"
            placeholder="default branch"
            value={ref}
            onChange={(event) => setRef(event.target.value)}
            className="h-9 w-full rounded-lg border bg-background px-3 font-mono text-sm"
            autoComplete="off"
            spellCheck={false}
          />
        </div>
        <p className="text-xs text-muted-foreground">
          Only github.com repositories up to 200 MB. The exact commit is recorded, and a shallow copy of it is cloned
          into an isolated sandbox. Scanning reads the repository. Nothing is written to it.
        </p>
        <Button type="submit" disabled={scan.isPending || !url.trim()}>
          {scan.isPending ? 'Resolving repository…' : 'Scan repository'}
        </Button>
        {scan.isError && (
          <div role="alert" className="space-y-1 text-sm text-destructive">
            <p>{scan.error.message}</p>
            {scan.error.code === 'private_repo_access_required' && (
              <a className="underline" href={githubLoginUrl({ privateRepos: true, next: '/upload' })}>
                Grant private repository access
              </a>
            )}
            {(scan.error.code === 'github_auth_required' || scan.error.code === 'github_rate_limited') &&
              !me.data &&
              config.data?.github_enabled && (
                <a className="underline" href={githubLoginUrl({ next: '/upload' })}>
                  Sign in with GitHub
                </a>
              )}
          </div>
        )}
      </form>

      {config.data?.github_enabled && (
        <div className="space-y-2 border-t pt-4">
          <h3 className="text-sm font-medium">Your repositories</h3>
          {!connected ? (
            <p className="text-sm text-muted-foreground">
              <a className="underline" href={githubLoginUrl({ next: '/upload' })}>
                Connect GitHub
              </a>{' '}
              to pick from your repositories. Public repositories can be scanned by URL without signing in.
            </p>
          ) : repos.isPending ? (
            <p className="text-sm text-muted-foreground">Loading repositories…</p>
          ) : repos.isError ? (
            <p className="text-sm text-destructive">Could not load repositories: {repos.error.message}</p>
          ) : (
            <>
              <input
                aria-label="Filter repositories"
                placeholder="Filter…"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                className="h-8 w-full rounded-lg border bg-background px-2.5 text-sm"
              />
              <ul className="max-h-72 divide-y overflow-y-auto rounded-lg border text-sm">
                {visible.map((repo) => {
                  const locked = repo.private && !privateAccess
                  return (
                    <li key={repo.full_name}>
                      <button
                        type="button"
                        disabled={locked}
                        title={locked ? 'Grant private repository access in Settings to scan this repository' : undefined}
                        onClick={() => {
                          setUrl(repo.html_url)
                          setRef('')
                        }}
                        className={cn(
                          'flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-50',
                          url === repo.html_url && 'bg-muted',
                        )}
                      >
                        {repo.private ? <Lock aria-label="private" className="size-3.5 shrink-0" /> : null}
                        <span className="truncate font-medium">{repo.full_name}</span>
                        <span className="ml-auto shrink-0 font-mono text-xs text-muted-foreground">
                          {repo.default_branch}
                        </span>
                      </button>
                    </li>
                  )
                })}
                {visible.length === 0 && <li className="px-3 py-2 text-muted-foreground">No repositories match.</li>}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  )
}

export function UploadPage() {
  return (
    <Card className="mx-auto max-w-xl">
      <CardHeader>
        <CardTitle>New scan</CardTitle>
        <CardDescription>
          Scan a codebase with Semgrep, Bandit, Ruff, OSV-Scanner and the architecture analyzer.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="github">
          <TabsList>
            <TabsTrigger value="github">GitHub repository</TabsTrigger>
            <TabsTrigger value="upload">Upload .zip</TabsTrigger>
          </TabsList>
          <TabsContent value="github" className="pt-3">
            <RepoScan />
          </TabsContent>
          <TabsContent value="upload" className="pt-3">
            <ZipUpload />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  )
}
