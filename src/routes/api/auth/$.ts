import { createFileRoute } from '@tanstack/solid-router'
import { getTanstackAuthForDatabase } from '../../../lib/auth'

const getDatabaseBindingFromRuntime = (): unknown => {
  const runtimeProcess = (
    globalThis as { process?: { env?: Record<string, unknown> } }
  ).process

  return runtimeProcess?.env?.DB
}

export const Route = createFileRoute('/api/auth/$')({
  server: {
    handlers: {
      GET: ({ request }) =>
        getTanstackAuthForDatabase(getDatabaseBindingFromRuntime()).handler(
          request,
        ),
      POST: ({ request }) =>
        getTanstackAuthForDatabase(getDatabaseBindingFromRuntime()).handler(
          request,
        ),
    },
  },
})
