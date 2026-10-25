import { basename } from 'node:path'
import type { ResolvedTarget } from '../scope/resolve-target.js'
import type { Entrypoint, Hotspot, LangStat, TargetProfile } from '../schema/target-profile.js'
import { detectStack } from './detect-stack.js'
import { readText, walkTarget } from './walk.js'
import type { FileRecord, WalkOptions } from './walk.js'

const JS_ROUTE = /\b(?:app|router|server|fastify)\.(get|post|put|patch|delete|all)\(\s*['"`]([^'"`]+)['"`]/g
const PY_ROUTE = /@\w+\.(route|get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]/g
const JS_ROUTE_FRAMEWORKS = ['express', 'fastify', 'koa', 'hono']
const PY_ROUTE_FRAMEWORKS = ['flask', 'fastapi']

const AUTH = /\b(passport|jsonwebtoken|jwt|bcrypt|req\.user|isAdmin|authenticate|authorize|login)\b/i
const DATA = /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[\s\S]{0,60}\b(?:FROM|INTO|SET)\b|\.(?:query|execute|raw|findOne)\(/
const UNTRUSTED = /\breq\.(?:body|query|params|headers)\b|\brequest\.(?:args|form|json)\b/
const SECRET_ASSIGN = /\b(?:password|secret|api_?key|token)\w*\s*[:=]\s*['"][^'"\s]+['"]/i

function routesIn(text: string, file: FileRecord, frameworks: string[]): Entrypoint[] {
  const re = file.language === 'javascript' || file.language === 'typescript'
    ? frameworks.some((f) => JS_ROUTE_FRAMEWORKS.includes(f)) ? JS_ROUTE : null
    : file.language === 'python' && frameworks.some((f) => PY_ROUTE_FRAMEWORKS.includes(f)) ? PY_ROUTE : null
  if (!re) return []
  return [...text.matchAll(re)].map((m) => ({ path: file.path, kind: 'http-route' as const, detail: `${(m[1] ?? '').toUpperCase()} ${m[2] ?? ''}` }))
}

function hotspotFor(text: string, file: FileRecord, hasRoutes: boolean): Hotspot | null {
  const reasons: string[] = []
  const domains = new Set<string>()
  const flag = (domain: string, reason: string): void => {
    domains.add(domain)
    reasons.push(reason)
  }
  if (hasRoutes) flag('authorization', 'defines HTTP routes; each needs an authorization check')
  if (AUTH.test(text)) flag('authorization', 'touches authentication or authorization logic')
  if (DATA.test(text)) flag('injection', 'accesses a data store')
  if (UNTRUSTED.test(text)) flag('injection', 'reads untrusted request input')
  if (basename(file.path).startsWith('.env')) flag('secrets', 'environment file committed to the repository')
  else if (SECRET_ASSIGN.test(text)) flag('secrets', 'assigns a secret-like value in source')
  return reasons.length === 0 ? null : { path: file.path, reason: reasons.join('; '), domains: [...domains] }
}

export async function profileTarget(target: ResolvedTarget, opts: WalkOptions = {}): Promise<TargetProfile> {
  const root = target.root // already a realpath; never re-resolved (R15)
  const { files, skipped, truncated } = await walkTarget(root, opts)
  const stack = await detectStack(root, files)

  const byLang = new Map<string, LangStat>()
  for (const f of files) {
    if (!f.language) continue
    const s = byLang.get(f.language) ?? { language: f.language, files: 0, bytes: 0 }
    s.files += 1
    s.bytes += f.bytes
    byLang.set(f.language, s)
  }

  const entrypoints: Entrypoint[] = []
  const hotspots: Hotspot[] = []
  for (const f of files) {
    if (!f.language && !basename(f.path).startsWith('.env')) continue
    const text = await readText(root, f.path, opts.maxFileBytes ?? 1_048_576)
    if (text === null) continue
    const routes = routesIn(text, f, stack.frameworks)
    entrypoints.push(...routes)
    const h = hotspotFor(text, f, routes.length > 0)
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
