import { basename } from 'node:path'
import { readText } from './walk.js'
import type { FileRecord } from './walk.js'

export type StackInfo = {
  frameworks: string[]
  auth_surfaces: string[]
  data_layer: string[]
  iac: string[]
  ci: string[]
  client_boundary: string[]
}

type Category = keyof StackInfo
// token -> [category, label]. Exact-name match for package.json/requirements.txt, substring for the rest.
type Table = Record<string, [Category, string][]>

const NPM: Table = {
  express: [['frameworks', 'express']],
  fastify: [['frameworks', 'fastify']],
  koa: [['frameworks', 'koa']],
  hono: [['frameworks', 'hono']],
  next: [['frameworks', 'next'], ['client_boundary', 'next']],
  '@nestjs/core': [['frameworks', 'nestjs']],
  react: [['client_boundary', 'react']],
  vue: [['client_boundary', 'vue']],
  passport: [['auth_surfaces', 'passport']],
  jsonwebtoken: [['auth_surfaces', 'jsonwebtoken']],
  'express-session': [['auth_surfaces', 'express-session']],
  bcrypt: [['auth_surfaces', 'bcrypt']],
  'next-auth': [['auth_surfaces', 'next-auth']],
  pg: [['data_layer', 'postgres']],
  mysql2: [['data_layer', 'mysql']],
  mongoose: [['data_layer', 'mongodb']],
  mongodb: [['data_layer', 'mongodb']],
  '@prisma/client': [['data_layer', 'prisma']],
  sequelize: [['data_layer', 'sequelize']],
  typeorm: [['data_layer', 'typeorm']],
  redis: [['data_layer', 'redis']],
}
const PIP: Table = {
  django: [['frameworks', 'django']],
  flask: [['frameworks', 'flask']],
  fastapi: [['frameworks', 'fastapi']],
  pyjwt: [['auth_surfaces', 'pyjwt']],
  'flask-login': [['auth_surfaces', 'flask-login']],
  'psycopg2': [['data_layer', 'postgres']],
  'psycopg2-binary': [['data_layer', 'postgres']],
  sqlalchemy: [['data_layer', 'sqlalchemy']],
  pymongo: [['data_layer', 'mongodb']],
}
const SUBSTRING: Record<string, Table> = {
  'go.mod': {
    'gin-gonic/gin': [['frameworks', 'gin']],
    'labstack/echo': [['frameworks', 'echo']],
    'gofiber/fiber': [['frameworks', 'fiber']],
    'lib/pq': [['data_layer', 'postgres']],
    'gorm.io/gorm': [['data_layer', 'gorm']],
  },
  'Cargo.toml': {
    'actix-web': [['frameworks', 'actix-web']],
    axum: [['frameworks', 'axum']],
    rocket: [['frameworks', 'rocket']],
    sqlx: [['data_layer', 'sqlx']],
    diesel: [['data_layer', 'diesel']],
  },
  'composer.json': {
    'laravel/framework': [['frameworks', 'laravel']],
    'symfony/framework-bundle': [['frameworks', 'symfony']],
  },
  Gemfile: {
    rails: [['frameworks', 'rails']],
    sinatra: [['frameworks', 'sinatra']],
    devise: [['auth_surfaces', 'devise']],
  },
}

const MAX_MANIFEST_BYTES = 1_048_576

function namesOf(file: string, text: string): string[] | null {
  if (file === 'package.json') {
    try {
      const j = JSON.parse(text) as Record<string, unknown>
      return ['dependencies', 'devDependencies', 'peerDependencies'].flatMap((k) => {
        const d = j[k]
        return d && typeof d === 'object' ? Object.keys(d) : []
      })
    } catch {
      return [] // unparseable manifest: claim nothing rather than guess
    }
  }
  if (file === 'requirements.txt') {
    return text.split('\n').map((l) => (l.trim().split(/[=<>~!\[;\s]/)[0] ?? '').toLowerCase())
  }
  return null
}

/** Declared dependencies only (plus file-name conventions for IaC/CI). Nothing is inferred from code, so nothing is guessed. */
export async function detectStack(root: string, files: FileRecord[]): Promise<StackInfo> {
  const found: Record<Category, Set<string>> = {
    frameworks: new Set(), auth_surfaces: new Set(), data_layer: new Set(), iac: new Set(), ci: new Set(), client_boundary: new Set(),
  }
  const add = (hits: [Category, string][] | undefined): void => hits?.forEach(([c, l]) => found[c].add(l))

  for (const f of files) {
    const name = basename(f.path)
    if (f.path.endsWith('.tf')) found.iac.add('terraform')
    if (name === 'Dockerfile' || name.startsWith('Dockerfile.')) found.iac.add('docker')
    if (/^docker-compose.*\.ya?ml$/.test(name)) found.iac.add('docker-compose')
    if (/^\.github\/workflows\/[^/]+\.ya?ml$/.test(f.path)) found.ci.add('github-actions')
    if (name === '.gitlab-ci.yml') found.ci.add('gitlab-ci')
    if (name === 'Jenkinsfile') found.ci.add('jenkins')

    const table = name === 'package.json' ? NPM : name === 'requirements.txt' ? PIP : SUBSTRING[name]
    if (!table) continue
    const text = await readText(root, f.path, MAX_MANIFEST_BYTES)
    if (text === null) continue
    const names = namesOf(name, text)
    // hasOwn: a hostile manifest may declare a dependency named "constructor" or "__proto__".
    if (names) for (const n of names) add(Object.hasOwn(table, n) ? table[n] : undefined)
    else {
      const lower = text.toLowerCase()
      for (const [token, hits] of Object.entries(table)) if (lower.includes(token)) add(hits)
    }
  }

  const out = (c: Category): string[] => [...found[c]].sort()
  return { frameworks: out('frameworks'), auth_surfaces: out('auth_surfaces'), data_layer: out('data_layer'), iac: out('iac'), ci: out('ci'), client_boundary: out('client_boundary') }
}
