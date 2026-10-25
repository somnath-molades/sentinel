import { basename } from 'node:path'
import type { ResolvedTarget } from '../scope/resolve-target.js'
import type { Domain } from '../registry/vocabulary.js'
import type { Entrypoint, Hotspot, LangStat, TargetProfile } from '../schema/target-profile.js'
import { detectStack, isManifest } from './detect-stack.js'
import { walkTarget } from './walk.js'
import type { FileRecord, WalkOptions } from './walk.js'

const JS_ROUTE = /\b(?:app|router|server|fastify)\.(get|post|put|patch|delete|all)\(\s*['"`]([^'"`]+)['"`]/g
const PY_ROUTE = /@\w+\.(route|get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]/g
const JS_ROUTE_FRAMEWORKS = ['express', 'fastify', 'koa', 'hono']
const PY_ROUTE_FRAMEWORKS = ['flask', 'fastapi']

const AUTH = /\b(passport|jsonwebtoken|jwt|bcrypt|req\.user|isAdmin|authenticate|authorize|login)\b/i
const DATA = /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,60}\b(?:FROM|INTO|SET)\b|\.(?:query|execute|raw|findOne)\(/
const UNTRUSTED = /\breq\.(?:body|query|params|headers)\b|\brequest\.(?:args|form|json)\b/
const SECRET_ASSIGN = /\b(?:password|secret|api_?key|token)\w*\s*[:=]\s*['"][^'"\s]+['"]/i

type Scan = { file: FileRecord; js: Entrypoint[]; py: Entrypoint[]; auth: boolean; data: boolean; untrusted: boolean; secret: boolean }

const routes = (text: string, file: FileRecord, re: RegExp): Entrypoint[] =>
  [...text.matchAll(re)].map((m) => ({ path: file.path, kind: 'http-route' as const, detail: `${(m[1] ?? '').toUpperCase()} ${m[2] ?? ''}` }))

/** Runs once per file inside the walk's single read; keeps only small findings, never the text. */
function scan(text: string, file: FileRecord): Scan {
  const js = file.language === 'javascript' || file.language === 'typescript'
  return {
    file,
    js: js ? routes(text, file, JS_ROUTE) : [],
    py: file.language === 'python' ? routes(text, file, PY_ROUTE) : [],
    auth: AUTH.test(text),
    data: DATA.test(text),
    untrusted: UNTRUSTED.test(text),
    secret: SECRET_ASSIGN.test(text),
  }
}

function hotspotFor(s: Scan, hasRoutes: boolean): Hotspot | null {
  const reasons: string[] = []
  const domains = new Set<Domain>()
  const flag = (domain: Domain, reason: string): void => {
    domains.add(domain)
    reasons.push(reason)
  }
  if (hasRoutes) flag('authorization', 'defines HTTP routes; each needs an authorization check')
  if (s.auth) flag('authorization', 'touches authentication or authorization logic')
  if (s.data) flag('injection', 'accesses a data store')
  if (s.untrusted) flag('injection', 'reads untrusted request input')
  if (basename(s.file.path).startsWith('.env')) flag('secrets', 'environment file committed to the repository')
  else if (s.secret) flag('secrets', 'assigns a secret-like value in source')
  return reasons.length === 0 ? null : { path: s.file.path, reason: reasons.join('; '), domains: [...domains] }
}

export async function profileTarget(target: ResolvedTarget, opts: WalkOptions = {}): Promise<TargetProfile> {
  const root = target.root // already a realpath; never re-resolved (R15)
  const manifests = new Map<string, string>()
  const scans: Scan[] = []
  // Every file is opened exactly once, by the walk; detectors consume that text and never re-open a path.
  const { files, skipped, truncated } = await walkTarget(root, opts, (f, text) => {
    if (isManifest(f.path)) manifests.set(f.path, text)
    if (f.language || basename(f.path).startsWith('.env')) scans.push(scan(text, f))
  })
  const stack = detectStack(files, manifests)

  const byLang = new Map<string, LangStat>()
  for (const f of files) {
    if (!f.language) continue
    const s = byLang.get(f.language) ?? { language: f.language, files: 0, bytes: 0 }
    s.files += 1
    s.bytes += f.bytes
    byLang.set(f.language, s)
  }

  const useJs = stack.frameworks.some((f) => JS_ROUTE_FRAMEWORKS.includes(f))
  const usePy = stack.frameworks.some((f) => PY_ROUTE_FRAMEWORKS.includes(f))
  const entrypoints: Entrypoint[] = []
  const hotspots: Hotspot[] = []
  for (const s of scans) {
    const r = [...(useJs ? s.js : []), ...(usePy ? s.py : [])]
    entrypoints.push(...r)
    const h = hotspotFor(s, r.length > 0)
    if (h) hotspots.push(h)
  }

  return {
    schema_version: 1,
    target,
    generated_at: new Date().toISOString(),
    languages: [...byLang.values()].sort((a, b) => b.bytes - a.bytes),
    ...stack,
    entrypoints,
    hotspots,
    skipped,
    file_count: files.length,
    truncated,
  }
}
