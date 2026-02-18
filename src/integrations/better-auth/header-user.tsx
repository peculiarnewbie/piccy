import { Show } from 'solid-js'
import { Link } from '@tanstack/solid-router'
import { authClient } from '../../lib/auth-client'

export default function BetterAuthHeader() {
  const session = authClient.useSession()

  return (
    <Show
      when={!session().isPending}
      fallback={<div class="h-8 w-8 rounded-full bg-surface-2 animate-pulse" />}
    >
      <Show
        when={session().data?.user}
        fallback={
          <Link to="/better-auth" class="btn btn-outline no-underline">
            Sign in
          </Link>
        }
      >
        {(user) => (
          <div class="flex items-center gap-2">
            <Show
              when={user().image}
              fallback={
                <div class="h-8 w-8 rounded-full bg-surface-2 border border-border-heavy flex items-center justify-center">
                  <span class="text-xs font-semibold text-text-dim">
                    {user().name?.charAt(0).toUpperCase() || 'U'}
                  </span>
                </div>
              }
            >
              {(image) => (
                <img
                  src={image()}
                  alt=""
                  class="h-8 w-8 rounded-full border border-border-heavy"
                />
              )}
            </Show>
            <button
              onClick={() => {
                void authClient.signOut()
              }}
              class="btn btn-outline"
            >
              Sign out
            </button>
          </div>
        )}
      </Show>
    </Show>
  )
}
