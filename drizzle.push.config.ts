import { defineConfig } from 'drizzle-kit'

const accountId = process.env.CLOUDFLARE_ACCOUNT_ID
const databaseId = process.env.CLOUDFLARE_DATABASE_ID ?? process.env.DB_ID
const token =
  process.env.CLOUDFLARE_D1_TOKEN ?? process.env.CLOUDFLARE_API_TOKEN

if (!accountId || !databaseId || !token) {
  throw new Error(
    'Missing Cloudflare D1 credentials. Set CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_DATABASE_ID (or DB_ID), and CLOUDFLARE_D1_TOKEN (or CLOUDFLARE_API_TOKEN).',
  )
}

export default defineConfig({
  schema: './src/db/schema.ts',
  dialect: 'sqlite',
  driver: 'd1-http',
  dbCredentials: {
    accountId,
    databaseId,
    token,
  },
  strict: true,
  verbose: true,
})
