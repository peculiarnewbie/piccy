import { Link } from '@tanstack/solid-router'
import { Show } from 'solid-js'
import { authClient } from '../lib/auth-client'

export default function TopBar(props: { onUploadClick?: () => void }) {
  const session = authClient.useSession()

  return (
    <nav class="fixed top-0 left-0 right-0 h-[54px] flex items-center justify-between px-5 bg-surface border-b-2 border-border z-50">
      {/* Left: Logo */}
      <Link
        to="/"
        class="font-display font-[800] text-[21px] tracking-[-0.8px] lowercase no-underline text-text"
      >
        piccy<span class="text-accent italic">!</span>
      </Link>

      {/* Center: Tabs */}
      <div class="flex items-center gap-0.5">
        <Link
          to="/"
          class="tab"
          activeProps={{ class: 'tab tab-active' }}
          activeOptions={{ exact: true }}
        >
          Upload
        </Link>
        <Link
          to="/library"
          class="tab"
          activeProps={{ class: 'tab tab-active' }}
          activeOptions={{ exact: true }}
        >
          Library
        </Link>
      </div>

      {/* Right: Actions */}
      <div class="flex items-center gap-2">
        <Show when={!session().isPending}>
          <Show
            when={session().data?.user}
            fallback={
              <Link to="/demo/better-auth" class="btn btn-outline no-underline">
                Sign in
              </Link>
            }
          >
            {(user) => (
              <div class="flex items-center gap-2">
                <Show
                  when={user().image}
                  fallback={
                    <div class="h-7 w-7 rounded-full bg-surface-2 border border-border-heavy flex items-center justify-center">
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
                      class="h-7 w-7 rounded-full border border-border-heavy"
                    />
                  )}
                </Show>
                <button
                  onClick={() => {
                    void authClient.signOut()
                  }}
                  class="btn btn-outline text-[12px] py-1 px-3"
                >
                  Sign out
                </button>
              </div>
            )}
          </Show>
        </Show>

        <Show when={props.onUploadClick}>
          <button class="btn btn-accent" onClick={props.onUploadClick}>
            Upload
          </button>
        </Show>
      </div>
    </nav>
  )
}
