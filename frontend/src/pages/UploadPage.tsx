import { useMutation } from '@tanstack/react-query'
import { CloudUpload, FileArchive } from 'lucide-react'
import { type DragEvent, useId, useState } from 'react'
import { useNavigate } from 'react-router'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { type ApiError, type ScanCreated, uploadScan } from '@/lib/api'
import { formatBytes } from '@/lib/format'
import { cn } from '@/lib/utils'

const MAX_UPLOAD_MB = 50

function validateFile(file: File): string | null {
  if (!file.name.toLowerCase().endsWith('.zip')) return 'Only .zip archives are accepted.'
  if (file.size === 0) return 'The selected file is empty.'
  if (file.size > MAX_UPLOAD_MB * 1024 * 1024) return `The archive exceeds the ${MAX_UPLOAD_MB} MB limit.`
  return null
}

export function UploadPage() {
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
    <Card className="mx-auto max-w-xl">
      <CardHeader>
        <CardTitle>New scan</CardTitle>
        <CardDescription>Upload a zipped codebase to scan it with Semgrep.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
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
      </CardContent>
    </Card>
  )
}
