import { DiffEditor } from '@monaco-editor/react'
import '@/lib/monaco'
import { languageForPath } from '@/lib/monaco'
import type { FileChange } from '@/lib/api'

function prefersDark() {
  return document.documentElement.classList.contains('dark') || window.matchMedia('(prefers-color-scheme: dark)').matches
}

/** Side-by-side diff of a verified patch (excerpts around the change). */
export default function PatchDiff({ change }: { change: FileChange }) {
  const lines = Math.max(change.original.split('\n').length, change.patched.split('\n').length)
  const height = Math.min(520, Math.max(160, lines * 19 + 24))
  return (
    <div className="overflow-hidden rounded-md border">
      <div className="flex items-center justify-between border-b bg-muted/50 px-2 py-1 font-mono text-xs">
        <span className="break-all">{change.path}</span>
        <span className="text-muted-foreground">from line {change.start_line}</span>
      </div>
      <DiffEditor
        height={height}
        original={change.original}
        modified={change.patched}
        language={languageForPath(change.path)}
        theme={prefersDark() ? 'vs-dark' : 'vs'}
        options={{
          readOnly: true,
          originalEditable: false,
          renderSideBySide: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          lineNumbers: (n: number) => String(n + change.start_line - 1),
          fontSize: 12,
          automaticLayout: true,
        }}
      />
    </div>
  )
}
