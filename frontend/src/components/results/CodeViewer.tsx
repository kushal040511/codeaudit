import Editor from '@monaco-editor/react'

type CodeViewerProps = {
  value: string
  language?: string
  path?: string
}

/**
 * Read-only code viewer for scanned files.
 *
 * TODO:
 * - finding annotations via monaco.editor.setModelMarkers / decorations in onMount
 * - bundle Monaco locally with `loader.config({ monaco })` instead of the default
 *   jsDelivr CDN (needed for CSP / offline deployments)
 */
export function CodeViewer({ value, language = 'plaintext', path }: CodeViewerProps) {
  return (
    <div className="h-96 overflow-hidden rounded-lg border">
      <Editor
        height="100%"
        value={value}
        language={language}
        path={path}
        options={{
          readOnly: true,
          domReadOnly: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
        }}
      />
    </div>
  )
}
