import { betterAuth } from 'better-auth'
import { drizzleAdapter } from 'better-auth/adapters/drizzle'
import { tanstackStartCookies } from 'better-auth/tanstack-start/solid'
import { drizzle } from 'drizzle-orm/d1'

import {
  authAccounts,
  authSessions,
  authUsers,
  authVerifications,
} from '../db/schema'

const authSchema = {
  user: authUsers,
  session: authSessions,
  account: authAccounts,
  verification: authVerifications,
}

let runtimeAuthDatabaseBinding: unknown

type D1DatabaseBinding = {
  prepare: (query: string) => unknown
}

const isD1DatabaseBinding = (value: unknown): value is D1DatabaseBinding => {
  if (typeof value !== 'object' || value === null) {
    return false
  }

  return typeof (value as { prepare?: unknown }).prepare === 'function'
}

let didWarnMissingAuthDatabaseBinding = false

export const setAuthDatabaseBinding = (databaseBinding: unknown): void => {
  runtimeAuthDatabaseBinding = databaseBinding
}

export const getAuthDatabaseBinding = (): unknown => {
  if (isD1DatabaseBinding(runtimeAuthDatabaseBinding)) {
    return runtimeAuthDatabaseBinding
  }

  return getD1Binding()
}

const warnMissingAuthDatabaseBinding = (): void => {
  if (didWarnMissingAuthDatabaseBinding) {
    return
  }

  didWarnMissingAuthDatabaseBinding = true
  console.warn(
    'Better Auth is running without a D1 binding. Auth data will not persist. Ensure process.env.DB is set from Worker bindings before auth handlers run.',
  )
}

const getRuntimeEnv = (): Record<string, unknown> | undefined => {
  const runtimeProcess = (
    globalThis as { process?: { env?: Record<string, unknown> } }
  ).process
  return runtimeProcess?.env
}

const getEnvString = (key: string): string | undefined => {
  const value = getRuntimeEnv()?.[key]
  if (typeof value !== 'string') {
    return undefined
  }

  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

const getD1Binding = (): unknown => {
  const value = getRuntimeEnv()?.DB
  if (isD1DatabaseBinding(value)) {
    return value
  }

  return undefined
}

type SocialProviderConfig = {
  clientId: string
  clientSecret: string
  scope?: Array<string>
}

const getSocialProviders = (): Record<string, SocialProviderConfig> => {
  const providers: Record<string, SocialProviderConfig> = {}

  const googleClientId = getEnvString('GOOGLE_CLIENT_ID')
  const googleClientSecret = getEnvString('GOOGLE_CLIENT_SECRET')

  if (googleClientId && googleClientSecret) {
    providers.google = {
      clientId: googleClientId,
      clientSecret: googleClientSecret,
    }
  }

  const discordClientId = getEnvString('DISCORD_CLIENT_ID')
  const discordClientSecret = getEnvString('DISCORD_CLIENT_SECRET')

  if (discordClientId && discordClientSecret) {
    providers.discord = {
      clientId: discordClientId,
      clientSecret: discordClientSecret,
      scope: ['identify', 'email'],
    }
  }

  return providers
}

type CreateAuthOptions = {
  useTanstackCookies: boolean
}

const createDatabaseAdapter = (databaseBinding: unknown) => {
  if (!isD1DatabaseBinding(databaseBinding)) {
    return undefined
  }

  const database = drizzle(databaseBinding as Parameters<typeof drizzle>[0], {
    schema: authSchema,
  })

  return drizzleAdapter(database, {
    provider: 'sqlite',
    schema: authSchema,
  })
}

const createAuth = (databaseBinding: unknown, options: CreateAuthOptions) => {
  const databaseAdapter = createDatabaseAdapter(databaseBinding)

  return betterAuth({
    appName: 'Piccy',
    baseURL: getEnvString('BETTER_AUTH_URL'),
    secret: getEnvString('BETTER_AUTH_SECRET'),
    ...(databaseAdapter ? { database: databaseAdapter } : {}),
    session: {
      cookieCache: {
        enabled: true,
        maxAge: 60 * 5,
      },
    },
    emailAndPassword: {
      enabled: false,
    },
    socialProviders: getSocialProviders(),
    plugins: options.useTanstackCookies ? [tanstackStartCookies()] : [],
  })
}

type AuthInstance = ReturnType<typeof createAuth>

export const auth = createAuth(getD1Binding(), {
  useTanstackCookies: true,
})

const workerAuthByDatabaseBinding = new WeakMap<object, AuthInstance>()
const tanstackAuthByDatabaseBinding = new WeakMap<object, AuthInstance>()

export const getAuthForDatabase = (databaseBinding: unknown): AuthInstance => {
  if (!isD1DatabaseBinding(databaseBinding)) {
    warnMissingAuthDatabaseBinding()
    return auth
  }

  const cached = workerAuthByDatabaseBinding.get(databaseBinding)
  if (cached) {
    return cached
  }

  const next = createAuth(databaseBinding, {
    useTanstackCookies: false,
  })
  workerAuthByDatabaseBinding.set(databaseBinding, next)
  return next
}

export const getTanstackAuthForDatabase = (
  databaseBinding: unknown,
): AuthInstance => {
  if (!isD1DatabaseBinding(databaseBinding)) {
    warnMissingAuthDatabaseBinding()
    return auth
  }

  const cached = tanstackAuthByDatabaseBinding.get(databaseBinding)
  if (cached) {
    return cached
  }

  const next = createAuth(databaseBinding, {
    useTanstackCookies: true,
  })
  tanstackAuthByDatabaseBinding.set(databaseBinding, next)
  return next
}
