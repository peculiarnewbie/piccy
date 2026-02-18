import {
  HeadContent,
  Outlet,
  Scripts,
  createRootRouteWithContext,
} from '@tanstack/solid-router'
import { TanStackRouterDevtools } from '@tanstack/solid-router-devtools'

import { HydrationScript } from 'solid-js/web'
import { Suspense } from 'solid-js'

import TopBar from '../components/TopBar'

import styleCss from '../styles.css?url'

const SITE_TITLE = 'Piccy - Grab, drop, share. Repeat.'
const SITE_DESCRIPTION =
  'A clipboard for your images. upload and share in <2 seconds.'
const SOCIAL_IMAGE_URL = '/og.png'
const SOCIAL_IMAGE_ALT =
  'Piccy upload and library preview with image cards and quick copy formats.'

export const Route = createRootRouteWithContext()({
  head: () => ({
    links: [
      { rel: 'preconnect', href: 'https://fonts.googleapis.com' },
      {
        rel: 'preconnect',
        href: 'https://fonts.gstatic.com',
        crossOrigin: 'anonymous' as const,
      },
      { rel: 'icon', href: '/favicon.ico' },
      { rel: 'manifest', href: '/manifest.json' },
      { rel: 'stylesheet', href: styleCss },
    ],
    meta: [
      { charset: 'utf-8' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1.0' },
      { title: SITE_TITLE },
      { name: 'description', content: SITE_DESCRIPTION },
      { name: 'theme-color', content: '#131624' },
      { property: 'og:type', content: 'website' },
      { property: 'og:site_name', content: 'Piccy' },
      { property: 'og:title', content: SITE_TITLE },
      { property: 'og:description', content: SITE_DESCRIPTION },
      { property: 'og:image', content: SOCIAL_IMAGE_URL },
      { property: 'og:image:alt', content: SOCIAL_IMAGE_ALT },
      { property: 'og:image:width', content: '891' },
      { property: 'og:image:height', content: '435' },
      { name: 'twitter:card', content: 'summary_large_image' },
      { name: 'twitter:title', content: SITE_TITLE },
      { name: 'twitter:description', content: SITE_DESCRIPTION },
      { name: 'twitter:image', content: SOCIAL_IMAGE_URL },
      { name: 'twitter:image:alt', content: SOCIAL_IMAGE_ALT },
    ],
  }),
  shellComponent: RootComponent,
})

function RootComponent() {
  return (
    <html>
      <head>
        <HydrationScript />
        <HeadContent />
      </head>
      <body>
        <Suspense>
          <TopBar />

          <Outlet />
          <TanStackRouterDevtools />
        </Suspense>
        <Scripts />
      </body>
    </html>
  )
}
