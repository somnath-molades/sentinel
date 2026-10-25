import { execFile } from 'node:child_process'
import { mkdtemp, realpath, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import type { Result } from '../types.js'

export type ResolvedTarget =
  | { kind: 'local'; root: string }
  | { kind: 'github'; owner: string; repo: string; root: string }
export type ScopeRefusal = { reason: string }
/** Runs `bin args`, with a time budget. Resolves with the exit code; rejects if it could not run at all (missing, timed out, killed). */
export type GhRunner = (args: string[], timeoutMs: number) => Promise<{ code: number; stdout: string }>

/** Exported for tests only; not part of the package index. GH_HOST pins the host as a second guard beside full-URL arguments. */
export const execRunner =
  (bin: string): GhRunner =>
  (args, timeoutMs) =>
    new Promise((res, rej) => {
      execFile(bin, args, { timeout: timeoutMs, maxBuffer: 1 << 20, env: { ...process.env, GH_HOST: 'github.com' } }, (err, stdout) => {
        if (!err) return res({ code: 0, stdout })
        const code = (err as { code?: unknown }).code
        if (typeof code === 'number') return res({ code, stdout })
        rej(err) // not installed, timed out, killed: caller refuses
      })
    })

const defaultGh = execRunner('gh')
const PROBE_MS = 30_000
const CLONE_MS = 600_000

const refuse = (reason: string): Result<ResolvedTarget, ScopeRefusal> => ({ ok: false, error: { reason } })
const ACCEPTED = 'Sentinel scans a local directory path, or a https://github.com/<owner>/<repo> repository you have access to.'
const NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/

// Path-boundary containment, not string prefix: /a/app-evil is not inside /a/app.
function contains(root: string, p: string): boolean {
  const rel = relative(root, p)
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel))
}

async function resolveLocal(input: string): Promise<Result<ResolvedTarget, ScopeRefusal>> {
  const given = resolve(input) // lexical: collapses '..' and trailing slashes
  try {
    // The given root is the real directory that holds the target; the target must resolve inside it.
    const root = await realpath(dirname(given))
    const real = await realpath(given)
    if (!contains(root, real)) {
      return refuse(`That path is a symlink to ${real}, which is outside the directory that holds it, so it was refused. If you mean to scan that location, pass ${real} directly.`)
    }
    if (!(await stat(real)).isDirectory()) return refuse('That path is not a directory. Give the directory containing the code to scan.')
    return { ok: true, value: { kind: 'local', root: real } }
  } catch {
    return refuse('That path does not exist or could not be read. Give an existing local directory.')
  }
}

function parseGitHub(input: string): { owner: string; repo: string } | null {
  let u: URL
  try {
    u = new URL(input)
  } catch {
    return null
  }
  if (u.protocol !== 'https:' || u.hostname !== 'github.com' || u.port || u.username || u.password || u.search || u.hash) return null
  const parts = u.pathname.replace(/\/$/, '').split('/').slice(1)
  if (parts.length !== 2) return null
  const owner = parts[0] ?? ''
  const repo = (parts[1] ?? '').replace(/\.git$/, '')
  return NAME.test(owner) && NAME.test(repo) && repo !== '.' && repo !== '..' ? { owner, repo } : null
}

async function resolveGitHub(input: string, gh: GhRunner): Promise<Result<ResolvedTarget, ScopeRefusal>> {
  const parsed = parseGitHub(input)
  if (!parsed) return refuse(`That is not a GitHub repository URL of the form https://github.com/<owner>/<repo>. ${ACCEPTED}`)
  const { owner, repo } = parsed
  const slug = `${owner}/${repo}`
  const noAccess = refuse(`Could not confirm the authenticated gh user has access to ${slug}. Check \`gh auth status\` and that you are authorized to scan this repository.`)
  // Full URL, not a bare slug: gh would otherwise pick the host from its own environment/config.
  const url = `https://github.com/${slug}`
  try {
    const probe = await gh(['repo', 'view', url, '--json', 'nameWithOwner'], PROBE_MS)
    if (probe.code !== 0) return noAccess
    const name: unknown = (JSON.parse(probe.stdout) as { nameWithOwner?: unknown }).nameWithOwner
    if (typeof name !== 'string' || name.toLowerCase() !== slug.toLowerCase()) return noAccess
  } catch {
    return noAccess
  }
  let tmp: string | undefined
  try {
    tmp = await mkdtemp(join(await realpath(tmpdir()), 'sentinel-'))
    const root = join(tmp, repo)
    const clone = await gh(['repo', 'clone', url, root, '--', '--depth', '1'], CLONE_MS)
    if (clone.code !== 0) throw new Error('clone failed')
    return { ok: true, value: { kind: 'github', owner, repo, root } }
  } catch {
    if (tmp) await rm(tmp, { recursive: true, force: true })
    return refuse(`Access to ${slug} was confirmed, but fetching it did not complete (it may have failed or timed out on a large repository). Try again.`)
  }
}

/** Fail-closed scope lock (spec 9.3): anything not provably in scope is refused. */
export async function resolveTarget(
  input: string,
  opts: { allowGitHub?: boolean; gh?: GhRunner } = {},
): Promise<Result<ResolvedTarget, ScopeRefusal>> {
  if (input.trim() === '' || input.includes('\0')) return refuse(`No usable target given. ${ACCEPTED}`)
  // Any scheme ("https:", "ssh:", "file:") or scp-style "git@host:" is a remote shape, never a local path.
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(input) || /^[^/\\]+@[^/\\]+:/.test(input)) {
    if (!opts.allowGitHub) return refuse(`Remote targets are not enabled. ${ACCEPTED}`)
    return resolveGitHub(input, opts.gh ?? defaultGh)
  }
  return resolveLocal(input)
}
