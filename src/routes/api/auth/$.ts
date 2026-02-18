import { createFileRoute } from '@tanstack/solid-router'
import {
  getAuthDatabaseBinding,
  getTanstackAuthForDatabase,
} from '../../../lib/auth'

export const Route = createFileRoute('/api/auth/$')({
  server: {
    handlers: {
      GET: ({ request }) =>
        getTanstackAuthForDatabase(getAuthDatabaseBinding()).handler(request),
      POST: ({ request }) =>
        getTanstackAuthForDatabase(getAuthDatabaseBinding()).handler(request),
    },
  },
})
