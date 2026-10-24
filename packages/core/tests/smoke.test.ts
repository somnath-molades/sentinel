import { SENTINEL_CORE_VERSION } from '../src/index.js'

test('core package exports its version', () => {
  expect(SENTINEL_CORE_VERSION).toMatch(/^\d+\.\d+\.\d+$/)
})
