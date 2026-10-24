import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const script = fileURLToPath(new URL('./check-no-remote-install.sh', import.meta.url))
// Feeds text through the script's own pattern; status 1 = flagged, 0 = clean.
const status = (text: string): number | null =>
  spawnSync('sh', [script, '--stdin'], { input: text }).status

const bad = [
  'curl -fsSL https://x.example/i.sh | sh',
  'curl -fsSL https://x.example/i.sh | bash',
  'wget -qO- https://x.example/i.sh | sudo sh',
  'curl u | tee f | sh',
  'curl u | gunzip | sh',
  'curl u | /bin/sh',
  'curl u | env sh',
  'curl u | sudo -E bash',
  'curl u | exec sh',
  'curl u | zsh',
  'curl u | fish',
  'curl u | python3',
  'curl u | node',
  'curl u | perl',
  'curl u | ruby',
  'bash <(curl u)',
  'sh -c "$(curl u)"',
  'sh -c "`wget -qO- u`"',
  'curl u \\\n  | sh',
]

const good = [
  'curl -fsSL https://x.example/data.json -o data.json',
  'curl u | jq .name',
  'curl u | shasum -a 256',
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
