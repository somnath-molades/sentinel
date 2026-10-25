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

type Opened = { kind: 'ok'; size: number; prefix: Buffer } | { kind: 'skip'; reason: SkipRecord['reason'] }

/** Reads at most PREFIX_BYTES of a regular file and its size; never the whole file. */
async function readPrefix(abs: string, maxBytes: number): Promise<Opened> {
  let fh
  try {
    fh = await open(abs, OPEN_FLAGS)
  } catch (e) {
    return { kind: 'skip', reason: (e as { code?: string }).code === 'ELOOP' ? 'not-regular' : 'unreadable' }
  }
  try {
    const st = await fh.stat()
    if (!st.isFile()) return { kind: 'skip', reason: 'not-regular' }
    if (st.size > maxBytes) return { kind: 'skip', reason: 'too-large' }
    const buf = Buffer.alloc(Math.min(st.size, PREFIX_BYTES))
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0)
    return { kind: 'ok', size: st.size, prefix: buf.subarray(0, bytesRead) }
  } catch {
    return { kind: 'skip', reason: 'unreadable' }
  } finally {
    await fh.close()
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

export async function walkTarget(root: string, opts: WalkOptions = {}): Promise<WalkResult> {
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
      if (entry.isSymbolicLink() || !(entry.isFile() || entry.isDirectory())) {
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
      // 3. Only now is the file opened, and only a bounded prefix is read.
      const o = await readPrefix(join(root, path), maxFileBytes)
      if (o.kind === 'skip') {
        skip(o.reason)
        continue
      }
      const reason = classifyPrefix(o.prefix, o.size)
      if (reason) {
        skip(reason)
        continue
      }
      // Cap is checked only for a file that would be included, so a skipped file never sets `truncated`.
      if (files.length >= maxFiles) {
        truncated = true
        return
      }
      files.push({ path, bytes: o.size, language: LANGUAGES[ext] ?? null })
    }
  }

  await visit('')
  return { files, skipped, truncated }
}

/** Bounded UTF-8 read of an already-walked file, for detectors. Same open flags as the walk. Returns null if it cannot be read. */
export async function readText(root: string, relPath: string, maxBytes: number): Promise<string | null> {
  let fh
  try {
    fh = await open(join(root, relPath), OPEN_FLAGS)
    const st = await fh.stat()
    if (!st.isFile() || st.size > maxBytes) return null
    const buf = Buffer.alloc(st.size)
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0)
    return buf.toString('utf8', 0, bytesRead)
  } catch {
    return null
  } finally {
    await fh?.close()
  }
}
