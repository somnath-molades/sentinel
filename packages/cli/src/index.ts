import { fileURLToPath } from 'node:url'
import { Command, CommanderError, InvalidArgumentError, Option } from 'commander'
import type { Severity } from '@sentinel/core'
import { packsAudit, packsList } from './commands/packs.js'
import { scan } from './commands/scan.js'
import { CliError, reason } from './context.js'
import type { Ctx, Deps, IO } from './context.js'

export type { Deps, IO } from './context.js'

const BANDS: Severity['band'][] = ['critical', 'high', 'medium', 'low', 'info']
const positiveInt = (s: string): number => {
  const n = Number(s)
  if (!Number.isInteger(n) || n < 1) throw new InvalidArgumentError('must be a positive integer.')
  return n
}
const registryOption = (): Option => new Option('--registry <dir>', 'registry directory (default: the bundled registry)')

// One function per command, each registered here. To add a command, write `registerX(program, ctx, setCode)`
// beside the others and call it from buildProgram.
function buildProgram(ctx: Ctx, setCode: (c: number) => void): Command {
  const program = new Command('sentinel').description('Defensive security scanner').exitOverride()
  program.configureOutput({ writeOut: ctx.io.out, writeErr: ctx.io.err })

  program
    .command('scan')
    .argument('<target>', 'local directory or https://github.com/<owner>/<repo>')
    .addOption(new Option('--format <format>', 'report format').choices(['markdown', 'sarif']).default('markdown'))
    .addOption(new Option('--fail-on <band>', 'exit 1 at or above this severity').choices(BANDS))
    .option('--max-files <n>', 'stop walking after n files', positiveInt)
    .addOption(registryOption())
    .action(async (target: string, o: { format: 'markdown' | 'sarif'; failOn?: Severity['band']; maxFiles?: number; registry?: string }) => {
      setCode(await scan(target, { format: o.format, failOn: o.failOn ?? null, ...(o.maxFiles !== undefined ? { maxFiles: o.maxFiles } : {}), ...(o.registry !== undefined ? { registry: o.registry } : {}) }, ctx))
    })

  const packs = program.command('packs').description('Inspect the technique registry')
  packs.command('list').addOption(registryOption()).action(async (o: { registry?: string }) => setCode(await packsList(o.registry, ctx)))
  packs.command('audit').addOption(registryOption()).action(async (o: { registry?: string }) => setCode(await packsAudit(o.registry, ctx)))
  return program
}

/** Runs the CLI and returns the exit code: 0 clean, 1 at or above --fail-on, 2 refusal or error. Never throws. */
export async function run(argv: string[], io: IO, deps: Deps = {}): Promise<number> {
  const defaultRegistry = fileURLToPath(new URL('../../../registry', import.meta.url))
  let code = 0
  try {
    await buildProgram({ io, deps, defaultRegistry }, (c) => (code = c)).parseAsync(argv, { from: 'user' })
    return code
  } catch (e) {
    if (e instanceof CommanderError) return e.exitCode === 0 ? 0 : 2 // commander already wrote its message to io.err
    io.err(`${e instanceof CliError ? '' : 'Internal error: '}${reason(e)}\n`) // a reason, never a stack
    return 2
  }
}
