import { pathToFileURL } from 'node:url'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { createSession, inputs } from './tools.js'
import type { SessionOptions } from './tools.js'

/** One server = one scan session (own findings store, own clone). Exactly the Phase 2a tool set. */
export function createSentinelServer(opts: SessionOptions = {}): { server: McpServer; close(): Promise<void> } {
  const s = createSession(opts)
  const server = new McpServer({ name: 'sentinel', version: '0.1.0' })
  server.registerTool('profile_target', { description: 'Scope-check and profile a target codebase (read-only). Starts a new scan session.', inputSchema: inputs.profile_target }, s.profile_target)
  server.registerTool('select_techniques', { description: 'Select detection techniques for a stack. Check `coverage`: "none" or "wildcard-only" means the stack is not (fully) covered, NOT that the code is clean.', inputSchema: inputs.select_techniques }, s.select_techniques)
  server.registerTool('plan_hunts', { description: 'Plan the hunt for the profiled target: one assignment per vulnerability domain, always all of them. Each lists applicable `techniques` (own-stack first), `hotspot_paths` (unranked paths worth reading first, never the only place: scan the whole target; they can be present even when `techniques` is empty), and `coverage`. `coverage` means only "this domain can be hunted here": it is the best across the target\'s stacks, so "exact" does not mean every language is covered; read each technique\'s `stacks`. "wildcard-only" means only generic techniques apply: partial coverage, not a clean result. An empty `techniques` list with a `reason` means nothing was examined for that domain: do not report it as clean. Each technique\'s `path` is relative to the top-level `registry_root` (an absolute directory): read `registry_root` joined with `path` to get that technique\'s `## Detection` and `## Verification` guidance, which is not included here. `target_root` is the absolute directory that was profiled: it is the whole scope to read, and no assignment carries a file list, so list the files there yourself. If `registry_warning` is present, some registry entries failed to load and an empty domain may be a load failure, not an absence.', inputSchema: {} }, s.plan_hunts)
  server.registerTool('record_finding', { description: 'Record candidate findings. Each is validated separately; rejected ones are listed with reasons.', inputSchema: inputs.record_finding }, s.record_finding)
  server.registerTool('verify_finding', { description: 'Record a verification verdict (and, for confirmations, severity factors 0..3) for a finding.', inputSchema: inputs.verify_finding }, s.verify_finding)
  server.registerTool('report', { description: 'Produce the report (markdown or sarif) and end the scan. Read `coverage_warnings`.', inputSchema: inputs.report }, s.report)
  // Closing the server also deletes any GitHub clone still on disk.
  const close = async (): Promise<void> => {
    await s.cleanup()
    await server.close()
  }
  server.server.onclose = () => void s.cleanup()
  return { server, close }
}

/** Stdio entry point. Local targets only unless SENTINEL_ALLOW_GITHUB=1 is set by the operator. */
export async function main(): Promise<void> {
  const { server, close } = createSentinelServer({ allowGitHub: process.env.SENTINEL_ALLOW_GITHUB === '1' })
  for (const sig of ['SIGINT', 'SIGTERM'] as const) process.once(sig, () => void close().finally(() => process.exit(0)))
  await server.connect(new StdioServerTransport())
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e: unknown) => {
    console.error(e instanceof Error ? e.message : String(e))
    process.exit(1)
  })
}
