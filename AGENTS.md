# AGENTS.md

This file is for autonomous/agentic coding agents operating in this repo.
Follow these conventions unless the user explicitly asks otherwise.

## Project Snapshot

- Name: `piccy`
- Runtime: TanStack Start + SolidJS + Cloudflare Workers
- Language: TypeScript (`strict: true`)
- Styling: Tailwind CSS v4 + `src/styles.css`
- Auth: Better Auth (social providers)
- DB: Cloudflare D1 via Drizzle
- Object storage: Cloudflare R2
- Package manager: Bun (`bun.lock` is present)

## Setup And Local Development

- Install deps: `bun install`
- Run dev server: `bun --bun run dev`
- Build production bundle: `bun --bun run build`
- Preview build: `bun --bun run preview`
- Start built server: `bun --bun run start`

## Lint / Format / Check

- Lint: `bun --bun run lint`
- Lint with fixes: `bun --bun run lint -- --fix .`
- Format write: `bun --bun run format -- --write .`
- Format check-only: `bun --bun run format -- --check .`
- Full fix pass: `bun --bun run check`
  - Runs `prettier --write . && eslint --fix`

## Test Commands (Vitest)

- Run all tests once: `bun --bun run test`
- Run one test file: `bun --bun run test -- src/path/to/file.test.ts`
- Run by test name: `bun --bun run test -- -t "test name"`
- Run one file + one test name: `bun --bun run test -- src/path/to/file.test.ts -t "test name"`
- Watch mode: `bunx --bun vitest`
- Current state: no `*.test.*` / `*.spec.*` files are committed yet

## Database Commands

- Generate migrations from schema changes: `bun --bun run db:generate`
- Push schema to remote D1: `bun --bun run db:push`
- Required env vars for `db:push`:
  - `CLOUDFLARE_ACCOUNT_ID`
  - `CLOUDFLARE_DATABASE_ID` or `DB_ID`
  - `CLOUDFLARE_D1_TOKEN` or `CLOUDFLARE_API_TOKEN`

## Code Style: Formatting And Syntax

- Prettier is authoritative:
  - `semi: false`
  - `singleQuote: true`
  - `trailingComma: 'all'`
- Prefer small composable helpers over monolithic blocks
- Avoid comments unless logic is non-obvious
- Use ASCII by default unless file already requires Unicode

## Code Style: Imports

- Use ESM imports only
- Import order:
  1. external packages
  2. local/project imports
  3. side-effect/style imports
- Separate groups with a blank line when readability improves
- Follow the repo's existing relative import style
- Do not introduce unused imports (TS enforces unused checks)

## Code Style: TypeScript

- Keep strict mode intact; do not weaken compiler settings
- Prefer explicit domain types (unions, narrow object shapes)
- Use `unknown` at boundaries and narrow before use
- Avoid `any`; if unavoidable, isolate and justify it
- Add explicit return types on non-trivial exported functions
- Keep client/server boundary types explicit (`Request`, `Response`, env)
- Use assertions sparingly; prefer runtime narrowing

## Naming Conventions

- Components: PascalCase (`TopBar`, `PiccyWorkspace`)
- Helpers/utilities: camelCase (`parseUploadError`)
- Route files: file-based naming in `src/routes`
- Constants: UPPER_SNAKE_CASE for shared limits/constants
- Booleans should read semantically: `is*`, `has*`, `can*`, `should*`
- Prefer descriptive names over abbreviations unless domain-standard

## SolidJS And Routing

- Use functional components
- Use `.tsx` for files containing JSX
- Prefer `createSignal`, `createEffect`, `onMount`, `onCleanup`
- In JSX, use Solid attributes (`class`, not `className`)
- Use file-based TanStack Router APIs (`createFileRoute`)
- Treat `src/routeTree.gen.ts` as generated; never hand-edit it

## Styling (Tailwind + CSS)

- Use utility-first Tailwind classes in markup
- Keep global tokens/utilities in `src/styles.css`
- Reuse existing design tokens (`--color-*`, `--font-*`) before adding new ones
- Use `@layer` for reusable component classes
- Keep responsive behavior explicit (`md:`, `xl:`, etc.)
- Preserve the current visual language unless redesign is requested

## Error Handling And Reliability

- Validate external input (HTTP body, query params, MIME/signature/size)
- Return structured JSON errors for API failures
- Use early returns for invalid state and method guards
- Wrap network/storage/DB operations in `try/catch`
- Log server failures with actionable context (`console.error` / `console.warn`)
- Do not leak secrets in logs or response payloads
- Prefer graceful client-side fallbacks
- For optimistic UI updates, include rollback on failure
- Keep ownership checks around user/anonymous resources
- Keep pagination cursor encode/decode defensive and strict
- Add cleanup paths for partial DB/storage failures

## Cursor And Copilot Rule Inclusions

- `.cursorrules` exists and must be honored
- `.cursor/rules/` directory was not found
- `.github/copilot-instructions.md` was not found

Rules sourced from `.cursorrules`:

- Prefer functional components
- Use `createSignal()` for reactive state
- Implement Tailwind classes for styling
- Keep TypeScript strict mode enabled
- Use Tailwind `@apply` for reusable CSS when appropriate
- Use responsive Tailwind variants
- Keep global Tailwind styles in `src/styles.css`
- Implement dark mode with Tailwind `dark:` variant when adding dark-mode behavior
- Use TanStack Router where applicable
- Use type-safe context with `createContext`
- Add proper typing for event handlers
- Follow TypeScript naming and typing best practices
- Use type assertions sparingly and only when necessary
- Use Tailwind `@layer` for custom style layers
- Follow utility-first CSS approach
- Follow SolidJS and Tailwind naming conventions
- Use Tailwind JIT mode (standard in modern Tailwind tooling)
