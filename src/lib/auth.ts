import { betterAuth } from 'better-auth'
import { tanstackStartCookies } from 'better-auth/tanstack-start/solid'

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
  if (typeof value === 'object' && value !== null) {
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

const createAuth = (databaseBinding: unknown, options: CreateAuthOptions) => {
  return betterAuth({
    appName: 'Piccy',
    baseURL: getEnvString('BETTER_AUTH_URL'),
    secret: getEnvString('BETTER_AUTH_SECRET'),
    ...(typeof databaseBinding === 'object' && databaseBinding !== null
      ? { database: databaseBinding as never }
      : {}),
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
  if (typeof databaseBinding !== 'object' || databaseBinding === null) {
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
  if (typeof databaseBinding !== 'object' || databaseBinding === null) {
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
