# Piccy Plan

## Purpose

Build the fastest image sharing flow on the web:

- paste, drag-drop, or click upload
- get a public link immediately
- copy direct URL, Markdown, or BBCode in one click
- let signed-in users manage their own library
- keep infra fully Cloudflare-native

## How This Plan Is Used

- This document is forward-looking only.
- Code, migrations, tests, and config are the source of truth for implementation state.
- No progress snapshots or detailed "what was done" logs live here.

## Core Decisions

- Frontend: SolidJS + Vite
- API/runtime: Cloudflare Workers + Hono
- Storage: Cloudflare R2
- Relational data: Cloudflare D1 via Drizzle
- Auth: Better Auth (OAuth providers only)
- Background work: Queues + Cloudflare Containers

## Product Requirements

- Fast first interaction (warm navigation target <1s)
- Paste-to-copied-link target p95 <2.5s for common image sizes
- No blocking modal flow after upload
- Keyboard-first behavior for upload and copy actions

## MVP Scope

### Upload + Share

- Support click upload, drag-drop, and global paste
- Validate uploads server-side (type/signature/size)
- Return share outputs: direct URL, Markdown, BBCode
- Auto-copy on single-image upload success

### Library

- Signed-in users can browse uploads in a dense, responsive masonry grid
- Signed-out users can still upload, with anonymous ownership and limits
- Cursor pagination for scalable library loading
- Click-to-copy as the default image-card action

### Auth

- OAuth only (Google + Discord)
- Smooth signed-out to signed-in transition
- Anonymous uploads can be associated with user account after sign-in

### Manage + Safety

- Ownership checks on manage/delete endpoints
- Soft-delete flow with async storage cleanup
- Baseline abuse controls (rate limiting, upload caps)

## API Surface (MVP)

- `POST /api/uploads`
- `POST /api/uploads/:id/copy`
- `GET /api/me/uploads?cursor=...`
- `DELETE /api/me/uploads/:id`
- `GET|POST /api/auth/*`

## UX Direction

- Single-page feel, no full-page navigation for core actions
- Image-first interface: upload in context, copy in one click
- Responsive masonry behavior from mobile to desktop
- Clear copy feedback (toasts + card-level visual confirmation)
- Accessible keyboard shortcuts for fast repeat usage

## Delivery Roadmap

### Now

- Finish core masonry UI and card interactions
- Complete delete UX and cleanup scheduling path
- Finalize keyboard navigation + touch-friendly copy behavior
- Add resiliency for transient upload failures

### Next

- Production hardening (domains, CORS, secrets, deploy pipeline)
- WebP + thumbnail optimization pipeline via queue/container
- Serve optimized variants when available with safe fallback

### Later

- Semantic image search (Workers AI + Vectorize)
- Advanced GIF optimization/transcoding pipeline

## Comprehensive TODO List

### Phase 0 - Platform Bootstrap

- [x] Worker entry serves app + API
- [x] Wrangler configured with D1 and R2 bindings
- [x] Node compatibility flags enabled for Better Auth runtime
- [x] Baseline scripts in place (`dev`, `build`, `db:generate`, `db:push`)

### Phase 1 - Data + Auth Foundation

- [x] Drizzle schema covers auth, uploads, and copy events
- [x] Base migrations exist for uploads, auth tables, and anonymous ownership
- [x] Better Auth handler mounted at `/api/auth/*`
- [x] OAuth-only auth path (Google + Discord)
- [x] Basic sign-in/sign-out UI is wired
- [ ] Replace demo-oriented auth flow with in-app auth popover/dropdown UX

### Phase 2 - Upload + Share Backend (MVP)

- [x] `POST /api/uploads` with strict server validation (type/signature/size)
- [x] R2 write + D1 insert with cleanup on metadata failure
- [x] Signed anonymous identity cookie flow
- [x] Anonymous upload cap enforcement (50 uploads)
- [x] Anonymous expiry assignment on upload creation
- [x] Public file serving route at `/i/:encodedR2Key` with cache headers
- [x] `POST /api/uploads/:id/copy` updates counts and persists copy events
- [x] `GET /api/me/uploads` supports user + anonymous ownership with cursor pagination
- [x] `DELETE /api/me/uploads/:id` soft-delete endpoint

### Phase 3 - Upload UI (Current State)

- [x] Click upload flow (single file)
- [x] Drag-drop flow (single file)
- [x] Global paste upload flow
- [x] Upload progress and error states
- [x] Auto-copy direct URL after successful upload
- [x] URL/Markdown/BBCode output copy actions
- [x] Copy tracking calls from uploader actions
- [x] Top bar with auth-aware sign-in/sign-out state
- [ ] Multi-file upload support
- [ ] Inline upload cards in a live library context
- [ ] Centralized toast stack (current feedback is inline message blocks)

### Phase 4 - Library UX Rebuild

- [x] Build real masonry library UI backed by `/api/me/uploads`
- [x] Add image cards with click-to-copy default behavior
- [x] Add per-card format picker (URL/MD/BB)
- [x] Implement infinite scroll with cursor continuation
- [x] Add skeleton/loading/empty states for library fetches
- [x] Add keyboard navigation shortcuts for grid interactions
- [x] Add delete action UX (confirm + optimistic update/error state)
- [x] Send copy tracking with `source: "library"` for card interactions

### Phase 5 - Hardening + Operations

- [ ] Add rate limiting (per IP and/or per user)
- [x] Add retry strategy for transient upload/network failures
- [ ] Add telemetry for upload latency, copy latency, and failures
- [ ] Add scheduled cleanup job for expired anonymous uploads
- [ ] Add scheduled cleanup job for soft-deleted uploads past grace period
- [ ] Audit ownership/authorization checks on all manage endpoints

### Phase 6 - Production Setup

- [ ] Finalize R2 public-domain and CORS policy
- [x] Worker route/custom domain is configured in Wrangler
- [ ] Document and validate required secrets/variables per environment
- [ ] Add CI pipeline for build + deploy
- [ ] Add remote smoke-test workflow

### Phase 7 - Optimization Pipeline

- [ ] Enqueue optimization jobs after upload writes
- [ ] Build container worker for WebP + thumbnail generation
- [ ] Persist optimization outputs/status updates in D1
- [ ] Prefer optimized variants when available with safe fallback
- [ ] Add retry/dead-letter handling for failed optimization jobs

### Phase 8 - Search + Advanced Media

- [ ] Add semantic search pipeline (Workers AI + Vectorize)
- [ ] Add semantic query API and UI integration
- [ ] Add GIF-specific optimization/transcoding pipeline

## MVP Acceptance Criteria

- A user can paste an image and end with a copied shareable link in one flow
- Upload by button, drag-drop, and paste all work reliably
- Library shows uploads in a responsive masonry layout
- Clicking an image copies the direct URL by default
- Copy format options (URL/Markdown/BBCode) are available per image
- Signed-in users can browse/manage only their own uploads
- Copy tracking persists and is queryable

## Guardrails

- Keep upload path fast: persist original first, optimize asynchronously
- Preserve original assets for compatibility and reprocessing
- Prefer Cloudflare-native services for storage, compute, and scheduling
- Treat reliability and speed as product features, not polish
