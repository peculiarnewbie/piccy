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

const getSocialProviders = (): Record<
  string,
  {
    clientId: string
    clientSecret: string
  }
> => {
  const providers: Record<
    string,
    {
      clientId: string
      clientSecret: string
    }
  > = {}

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
    }
  }

  return providers
}

export const auth = betterAuth({
  appName: 'Piccy',
  baseURL: getEnvString('BETTER_AUTH_URL'),
  secret: getEnvString('BETTER_AUTH_SECRET'),
  database: getD1Binding() as never,
  emailAndPassword: {
    enabled: false,
  },
  socialProviders: getSocialProviders(),
  plugins: [tanstackStartCookies()],
})
