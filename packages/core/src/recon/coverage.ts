import { stackForLanguage } from '../registry/vocabulary.js'
import type { TargetProfile } from '../schema/target-profile.js'

/**
 * Coverage loss that is derivable from a profile alone, in one place so every consumer says the same thing.
 * Derived from file counts, never from the set of languages that happen to be present: one recognised file
 * in a tree of unrecognised ones used to produce a stack and no warning at all.
 */
export type CoverageGap = {
  /** Stack tokens derivable from the profile's languages. */
  stacks: string[]
  /** Present languages with no stack. Empty when the unexamined files carry no recognised language at all. */
  unmapped_languages: string[]
  /** Scanned files carrying a language Sentinel recognises. */
  files_with_language: number
  /** Scanned files not carrying a recognised language: examined by no stack-specific technique. */
  files_without_language: number
  files_scanned: number
  /**
   * Coverage warnings in reading order. `blocks` says whether a severity gate can still be meaningfully
   * evaluated: it is false only for the unexamined-share warning, because almost every real repository holds
   * some file with no recognised language (a README, a manifest), and a gate that can never pass is not a gate.
   */
  warnings: { text: string; blocks: boolean }[]
}

export function coverageGap(profile: TargetProfile): CoverageGap {
  const languages = profile.languages.map((l) => l.language)
  const stacks = [...new Set(languages.flatMap((l) => stackForLanguage(l) ?? []))].sort()
  const unmapped = languages.filter((l) => stackForLanguage(l) === undefined)
  const withLang = profile.languages.reduce((n, l) => n + l.files, 0)
  const without = profile.file_count - withLang

  const warnings: CoverageGap['warnings'] = []
  const warn = (text: string, blocks = true): void => void warnings.push({ text, blocks })
  if (unmapped.length) warn(`No technique stack exists for: ${unmapped.join(', ')}. Code in those languages is NOT examined by stack-specific techniques; do not read it as clean.`)
  if (stacks.length === 0) warn("No stack could be derived from this target's files. Stack-specific techniques will not apply; an empty report is NOT a clean result.")
  if (without > 0) {
    const pct = Math.round((without / profile.file_count) * 100)
    warn(
      `Of ${profile.file_count} file${profile.file_count === 1 ? '' : 's'} scanned, ${withLang} carr${withLang === 1 ? 'ies' : 'y'} a language Sentinel recognises. The other ${without} (${pct}%) — including any infrastructure-as-code, configuration and other unrecognised files — were examined by no stack-specific technique. An empty report is NOT a clean result for them.`,
      false,
    )
  }
  if (profile.truncated) {
    warn('The file limit was reached, so the scan stopped early: files beyond the limit were not examined at all, the skipped list is incomplete, and the stack derived here may not be the project\'s. An empty report is NOT a clean result.')
  }
  return { stacks, unmapped_languages: unmapped, files_with_language: withLang, files_without_language: without, files_scanned: profile.file_count, warnings }
}
