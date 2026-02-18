import { createFileRoute } from '@tanstack/solid-router'
import { Show, createSignal } from 'solid-js'
import { authClient } from '../lib/auth-client'

export const Route = createFileRoute('/better-auth')({
  component: BetterAuthPage,
})

function BetterAuthPage() {
  const session = authClient.useSession()
  const [error, setError] = createSignal('')
  const [loadingProvider, setLoadingProvider] = createSignal<
    'google' | 'discord' | null
  >(null)

  const signInWithProvider = async (provider: 'google' | 'discord') => {
    setError('')
    setLoadingProvider(provider)

    try {
      const result = await authClient.signIn.social({
        provider,
        callbackURL: '/',
      })

      if (result.error) {
        setError(result.error.message || 'Unable to start sign-in.')
        return
      }
    } catch {
      setError('Unable to start sign-in right now.')
    } finally {
      setLoadingProvider(null)
    }
  }

  return (
    <Show
      when={!session().isPending}
      fallback={
        <div class="flex items-center justify-center py-10">
          <div class="h-5 w-5 animate-spin rounded-full border-2 border-neutral-200 border-t-neutral-900" />
        </div>
      }
    >
      <Show
        when={session().data?.user}
        fallback={
          <div class="mx-auto w-full max-w-md space-y-6 px-4 py-10">
            <div class="space-y-2">
              <h1 class="text-2xl font-semibold">Sign in to Piccy</h1>
              <p class="text-sm text-neutral-500">
                Choose a provider to continue.
              </p>
            </div>

            <div class="space-y-4">
              <button
                type="button"
                disabled={loadingProvider() !== null}
                onClick={() => {
                  void signInWithProvider('google')
                }}
                class="inline-flex h-10 w-full items-center justify-center rounded-md bg-neutral-900 px-4 text-sm font-medium text-white transition hover:bg-neutral-800 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loadingProvider() === 'google'
                  ? 'Redirecting to Google...'
                  : 'Continue with Google'}
              </button>

              <button
                type="button"
                disabled={loadingProvider() !== null}
                onClick={() => {
                  void signInWithProvider('discord')
                }}
                class="inline-flex h-10 w-full items-center justify-center rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-900 transition hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loadingProvider() === 'discord'
                  ? 'Redirecting to Discord...'
                  : 'Continue with Discord'}
              </button>

              <Show when={error()}>
                <div class="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700">
                  {error()}
                </div>
              </Show>
            </div>
          </div>
        }
      >
        {(user) => (
          <div class="mx-auto w-full max-w-md space-y-6 px-4 py-10">
            <div class="space-y-2">
              <h1 class="text-2xl font-semibold">You are signed in</h1>
              <p class="text-sm text-neutral-500">
                Signed in as {user().email}
              </p>
            </div>

            <button
              type="button"
              onClick={() => {
                void authClient.signOut()
              }}
              class="inline-flex h-10 w-full items-center justify-center rounded-md border border-neutral-300 bg-white px-4 text-sm font-medium text-neutral-900 transition hover:bg-neutral-100"
            >
              Sign out
            </button>
          </div>
        )}
      </Show>
    </Show>
  )
}
