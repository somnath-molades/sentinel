import { createHash } from 'node:crypto'

export type FindingInput = { technique_id: string; file: string; line: number; snippet: string }

// Line is excluded and whitespace collapsed so reformatting cannot resurrect a closed finding.
export function fingerprint(f: FindingInput): string {
  const snippet = f.snippet.replace(/\s+/g, ' ').trim()
  return createHash('sha256').update(`${f.technique_id}\0${f.file}\0${snippet}`).digest('hex').slice(0, 16)
}
