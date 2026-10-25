#!/usr/bin/env node
import { run } from './index.js'

process.exitCode = await run(process.argv.slice(2), { out: (s) => void process.stdout.write(s), err: (s) => void process.stderr.write(s) })
