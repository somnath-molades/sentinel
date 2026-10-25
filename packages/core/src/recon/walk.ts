import { constants } from 'node:fs'
import { open, readdir } from 'node:fs/promises'
import { extname, join } from 'node:path'
import type { SkipRecord } from '../schema/target-profile.js'

export type FileRecord = { path: string; bytes: number; language: string | null }
export type WalkOptions = { maxFiles?: number; maxFileBytes?: number }
export type WalkResult = { files: FileRecord[]; skipped: SkipRecord[]; truncated: boolean }

const PREFIX_BYTES = 64 * 1024
const MINIFIED_MIN_PREFIX = 2000
const MINIFIED_AVG_LINE = 200

const VENDORED_DIRS = new Set(['node_modules', 'vendor', 'bower_components', '.git'])
const GENERATED_DIRS = new Set(['dist', 'build'])
const LOCKFILES = new Set(['pnpm-lock.yaml', 'package-lock.json', 'yarn.lock', 'Cargo.lock', 'composer.lock', 'Gemfile.lock', 'poetry.lock', 'go.sum'])
const BINARY_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.pdf', '.zip', '.gz', '.tar', '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.so', '.dll', '.dylib', '.exe', '.class', '.jar', '.wasm'])
const LANGUAGES: Record<string, string> = {
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.py': 'python', '.go': 'go', '.rs': 'rust',
  '.php': 'php', '.rb': 'ruby', '.java': 'java', '.cs': 'csharp', '.sh': 'shell',
}

/**
 * Open for reading only. O_NOFOLLOW makes a final-component symlink swapped in after readdir fail (ELOOP)
 * instead of being followed; O_NONBLOCK stops a swapped-in FIFO from hanging the open.
 */
const OPEN_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK

type Opened = { kind: 'ok'; size: number; text: string } | { kind: 'skip'; reason: SkipRecord['reason'] }

/**
 * The ONLY place a target file is opened. Reads a bounded prefix first and classifies it; the rest of the file
 * (at most maxBytes, checked before any allocation) is read only if the prefix passes. The text is handed to
 * the caller so no later stage re-opens the path.
 */
async function readFileOnce(abs: string, maxBytes: number): Promise<Opened> {
  let fh
  try {
    fh = await open(abs, OPEN_FLAGS)
  } catch (e) {
    return { kind: 'skip', reason: (e as { code?: string }).code === 'ELOOP' ? 'symlink' : 'unreadable' }
  }
  try {
    const st = await fh.stat()
    if (!st.isFile()) return { kind: 'skip', reason: 'not-regular' }
    if (st.size > maxBytes) return { kind: 'skip', reason: 'too-large' }
    const buf = Buffer.alloc(st.size)
    const head = await fh.read(buf, 0, Math.min(st.size, PREFIX_BYTES), 0)
    const reason = classifyPrefix(buf.subarray(0, head.bytesRead), st.size)
    if (reason) return { kind: 'skip', reason }
    let got = head.bytesRead
    while (got < st.size) {
      const { bytesRead } = await fh.read(buf, got, st.size - got, got)
      if (bytesRead === 0) break
      got += bytesRead
    }
    return { kind: 'ok', size: st.size, text: buf.toString('utf8', 0, got) }
  } catch {
    return { kind: 'skip', reason: 'unreadable' }
  } finally {
    // A failing close (EIO) must not replace the return value or abandon sibling entries.
    await fh.close().catch(() => undefined)
  }
}

/** Content checks on the bounded prefix only. Returns a skip reason or null. */
function classifyPrefix(prefix: Buffer, size: number): SkipRecord['reason'] | null {
  if (prefix.includes(0)) return 'binary'
  let text: string
  try {
    // stream:true tolerates a multi-byte character cut by the prefix boundary.
    text = new TextDecoder('utf-8', { fatal: true }).decode(prefix, { stream: size > prefix.length })
  } catch {
    return 'not-utf8'
  }
  // shortcut: only the first 64KiB is validated/inspected, so a bad byte or a minified tail beyond it is not seen; upgrade to a streaming scan if that matters.
  const lines = text.split('\n').length
  if (text.length >= MINIFIED_MIN_PREFIX && text.length / lines > MINIFIED_AVG_LINE) return 'minified'
  return null
}

/** `onFile` receives each INCLUDED file's text from the walk's single read, so detectors never re-open a path. */
export async function walkTarget(root: string, opts: WalkOptions = {}, onFile?: (file: FileRecord, text: string) => void): Promise<WalkResult> {
  const maxFiles = opts.maxFiles ?? 10_000
  const maxFileBytes = opts.maxFileBytes ?? 1_048_576
  const files: FileRecord[] = []
  const skipped: SkipRecord[] = []
  let truncated = false

  // `root` is already a realpath (ResolvedTarget); it is used as given, never re-resolved.
  async function visit(rel: string): Promise<void> {
    const entries = await readdir(rel === '' ? root : join(root, rel), { withFileTypes: true })
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    for (const entry of entries) {
      if (truncated) return
      const path = rel === '' ? entry.name : `${rel}/${entry.name}`
      const skip = (reason: SkipRecord['reason']): void => void skipped.push({ path, reason })

      // 1. Type from the directory listing alone: symlinks and special files are never opened or followed.
      if (entry.isSymbolicLink()) {
        skip('symlink')
        continue
      }
      if (!(entry.isFile() || entry.isDirectory())) {
        skip('not-regular')
        continue
      }
      // 2. Path patterns, before any byte is read.
      if (entry.isDirectory()) {
        if (VENDORED_DIRS.has(entry.name)) skip('vendored')
        else if (GENERATED_DIRS.has(entry.name)) skip('generated')
        else {
          try {
            await visit(path)
          } catch {
            skip('unreadable')
          }
        }
        continue
      }
      if (LOCKFILES.has(entry.name)) {
        skip('generated')
        continue
      }
      const ext = extname(entry.name).toLowerCase()
      if (BINARY_EXT.has(ext)) {
        skip('binary')
        continue
      }
      // 3. Only now is the file opened, classified on a bounded prefix, and read once; later stages reuse that text.
      const o = await readFileOnce(join(root, path), maxFileBytes)
      if (o.kind === 'skip') {
        skip(o.reason)
        continue
      }
      // Cap is checked only for a file that would be included, so a skipped file never sets `truncated`.
      if (files.length >= maxFiles) {
        truncated = true
        return
      }
      const rec: FileRecord = { path, bytes: o.size, language: LANGUAGES[ext] ?? null }
      files.push(rec)
      onFile?.(rec, o.text)
    }
  }

  await visit('')
  return { files, skipped, truncated }
}

