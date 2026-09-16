// Bundle Monaco locally instead of @monaco-editor/react's default CDN download, and
// load only the editor core, syntax highlighting and the editor worker (diffs run there).
import { loader } from '@monaco-editor/react'
import * as monaco from 'monaco-editor/editor.js'
import 'monaco-editor/basic-languages/monaco.contribution.js'
import EditorWorker from 'monaco-editor/editor/editor.worker.js?worker'

self.MonacoEnvironment = { getWorker: () => new EditorWorker() }
loader.config({ monaco })

const LANGUAGES: Record<string, string> = {
  py: 'python',
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  json: 'json',
  toml: 'ini',
  txt: 'plaintext',
  yml: 'yaml',
  yaml: 'yaml',
}

export function languageForPath(path: string): string {
  const extension = path.split('.').pop()?.toLowerCase() ?? ''
  return LANGUAGES[extension] ?? 'plaintext'
}
