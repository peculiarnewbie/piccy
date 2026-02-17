import { createFileRoute } from '@tanstack/solid-router'
import { PiccyWorkspace } from './index'

export const Route = createFileRoute('/library')({
  component: LibraryRoute,
})

function LibraryRoute() {
  return <PiccyWorkspace view="library" />
}
