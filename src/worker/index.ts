import handler from '@tanstack/solid-start/server-entry'
import { auth } from '../lib/auth'

const MAX_UPLOAD_SIZE_BYTES = 15 * 1024 * 1024
const MAX_ANONYMOUS_UPLOADS = 25
const MAX_USER_UPLOADS = 250
const MAX_PAID_USER_UPLOADS = 10_000
const ANONYMOUS_UPLOAD_EXPIRY_DAYS = 30
const SOFT_DELETE_GRACE_PERIOD_DAYS = 7
const PAID_MULTI_UPLOAD_BATCH_FIELD = 'batchSize'
const SESSION_LOOKUP_TIMEOUT_MS = 4_000
const SESSION_LOOKUP_MAX_ATTEMPTS = 2
const AUTH_SESSION_LOOKUP_TIMEOUT_MESSAGE = 'Auth session lookup timed out'
const LIBRARY_PAGE_SIZE = 30
const CLEANUP_BATCH_SIZE = 50
const MAX_CLEANUP_BATCHES_PER_RUN = 5
const TELEMETRY_RETENTION_DAYS = 30
const RATE_LIMIT_RETENTION_HOURS = 24
const ANONYMOUS_COOKIE_NAME = 'piccy_anon_id'
const ANONYMOUS_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365
const AUTH_SESSION_COOKIE_NAMES = new Set([
  'better-auth.session_token',
  '__Secure-better-auth.session_token',
  '__Host-better-auth.session_token',
])
const ULID_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const ULID_REGEX = /^[0-9A-HJKMNP-TV-Z]{26}$/

const MINUTE_MS = 60 * 1000

const RATE_LIMIT_RULES = {
  upload: [
    { scope: 'ip', windowMs: 10 * MINUTE_MS, maxRequests: 30 },
    { scope: 'user', windowMs: 10 * MINUTE_MS, maxRequests: 80 },
    { scope: 'anonymous', windowMs: 10 * MINUTE_MS, maxRequests: 20 },
  ],
  copy: [
    { scope: 'ip', windowMs: 5 * MINUTE_MS, maxRequests: 300 },
    { scope: 'user', windowMs: 5 * MINUTE_MS, maxRequests: 600 },
  ],
  delete: [
    { scope: 'ip', windowMs: 10 * MINUTE_MS, maxRequests: 80 },
    { scope: 'user', windowMs: 10 * MINUTE_MS, maxRequests: 200 },
    { scope: 'anonymous', windowMs: 10 * MINUTE_MS, maxRequests: 40 },
  ],
} as const

const MIME_TO_EXTENSION: Record<string, string> = {
  'image/png': 'png',
  'image/jpeg': 'jpg',
  'image/gif': 'gif',
  'image/webp': 'webp',
}

const EXTENSION_TO_MIME: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
}

interface Env {
  DB: {
    prepare: (query: string) => {
      bind: (...values: Array<unknown>) => {
        run: () => Promise<unknown>
        first: <T = Record<string, unknown>>() => Promise<T | null>
        all: <T = Record<string, unknown>>() => Promise<{
          results?: Array<T>
        }>
      }
    }
  }
  BUCKET: {
    put: (
      key: string,
      value: ArrayBuffer,
      options?: {
        httpMetadata?: {
          contentType?: string
        }
      },
    ) => Promise<unknown>
    get: (key: string) => Promise<{
      body: ReadableStream | null
      httpEtag: string
      writeHttpMetadata: (headers: Headers) => void
    } | null>
    delete: (key: string) => Promise<unknown>
  }
}

interface WorkerHandler {
  fetch: (
    request: Request,
    env: Env,
    context: WorkerExecutionContext,
  ) => Promise<Response>
  scheduled: (
    controller: WorkerScheduledController,
    env: Env,
    context: WorkerExecutionContext,
  ) => void
}

interface WorkerExecutionContext {
  waitUntil: (promise: Promise<unknown>) => void
}

interface WorkerScheduledController {
  cron: string
  scheduledTime: number
}

type UploadResponse = {
  id: string
  directUrl: string
  markdown: string
  bbcode: string
}

type CopyFormat = 'direct' | 'markdown' | 'bbcode'
type CopySource = 'uploader' | 'library' | 'detail'

type PaginationCursor = {
  createdAt: string
  id: string
}

type UploadQueryRow = {
  id: string
  r2_key: string
  public_url: string
  mime_type: string
  size_bytes: number
  width: number | null
  height: number | null
  copy_count: number
  created_at: string
  thumb_r2_key: string | null
  webp_r2_key: string | null
  webp_size_bytes: number | null
  optimization_status: string
}

type UploadListItem = {
  id: string
  directUrl: string
  markdown: string
  bbcode: string
  thumbUrl: string
  webpUrl: string | null
  mimeType: string
  sizeBytes: number
  width: number | null
  height: number | null
  copyCount: number
  optimizationStatus: string
  createdAt: string
}

type IdentityResolutionOptions = {
  ensureAnonymousId: boolean
  migrateAnonymousToUser: boolean
}

type RequestIdentity = {
  userId: string | null
  userEmail: string | null
  isPaidUser: boolean
  anonymousId: string | null
  setCookieHeader: string | null
  authSessionLookupFailed: boolean
}

type AuthenticatedUser = {
  id: string
  email: string | null
}

type OwnerField = 'owner_user_id' | 'owner_anon_id'

type OwnerScope = {
  ownerField: OwnerField
  ownerId: string
}

type RateLimitScope = 'ip' | 'user' | 'anonymous'
type RateLimitedOperation = keyof typeof RATE_LIMIT_RULES

type RateLimitRule = {
  scope: RateLimitScope
  windowMs: number
  maxRequests: number
}

type RequestTelemetryType = 'upload' | 'copy'

type CleanupUploadRow = {
  id: string
  r2_key: string
  thumb_r2_key: string | null
  webp_r2_key: string | null
}

const respondJson = (
  body: Record<string, unknown>,
  status = 200,
  headers?: HeadersInit,
): Response => {
  const responseHeaders = new Headers(headers)
  responseHeaders.set('content-type', 'application/json; charset=utf-8')

  return new Response(JSON.stringify(body), {
    status,
    headers: responseHeaders,
  })
}

const withSetCookieHeader = (
  response: Response,
  setCookieHeader: string | null,
): Response => {
  if (!setCookieHeader) {
    return response
  }

  const headers = new Headers(response.headers)
  headers.append('set-cookie', setCookieHeader)

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

const respondAuthSessionUnavailable = (
  setCookieHeader: string | null,
): Response => {
  return withSetCookieHeader(
    respondJson(
      {
        error:
          'Authentication session is temporarily unavailable. Please retry.',
      },
      503,
    ),
    setCookieHeader,
  )
}

const methodNotAllowed = (allowedMethod: string): Response => {
  return new Response('Method Not Allowed', {
    status: 405,
    headers: {
      allow: allowedMethod,
    },
  })
}

const getFileExtension = (filename: string): string | null => {
  const lastDot = filename.lastIndexOf('.')
  if (lastDot === -1) {
    return null
  }

  const extension = filename.slice(lastDot + 1).toLowerCase()
  return extension.length > 0 ? extension : null
}

const encodeTimePart = (time: number): string => {
  let value = time
  let encoded = ''

  for (let i = 0; i < 10; i += 1) {
    encoded = `${ULID_ALPHABET[value % 32]}${encoded}`
    value = Math.floor(value / 32)
  }

  return encoded
}

const encodeRandomPart = (): string => {
  const randomBytes = crypto.getRandomValues(new Uint8Array(16))
  let encoded = ''

  for (const randomByte of randomBytes) {
    encoded += ULID_ALPHABET[randomByte % 32]
  }

  return encoded
}

const createUlid = (): string => {
  return `${encodeTimePart(Date.now())}${encodeRandomPart()}`
}

const hasSignature = (bytes: Uint8Array, signature: Array<number>): boolean => {
  if (bytes.length < signature.length) {
    return false
  }

  for (let i = 0; i < signature.length; i += 1) {
    if (bytes[i] !== signature[i]) {
      return false
    }
  }

  return true
}

const hasWebpSignature = (bytes: Uint8Array): boolean => {
  if (bytes.length < 12) {
    return false
  }

  const riff = [0x52, 0x49, 0x46, 0x46]
  const webp = [0x57, 0x45, 0x42, 0x50]

  return (
    hasSignature(bytes, riff) &&
    bytes[8] === webp[0] &&
    bytes[9] === webp[1] &&
    bytes[10] === webp[2] &&
    bytes[11] === webp[3]
  )
}

const hasValidImageSignature = (
  bytes: Uint8Array,
  mimeType: string,
): boolean => {
  if (mimeType === 'image/png') {
    return hasSignature(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
  }

  if (mimeType === 'image/jpeg') {
    return hasSignature(bytes, [0xff, 0xd8, 0xff])
  }

  if (mimeType === 'image/gif') {
    return (
      hasSignature(bytes, [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]) ||
      hasSignature(bytes, [0x47, 0x49, 0x46, 0x38, 0x39, 0x61])
    )
  }

  if (mimeType === 'image/webp') {
    return hasWebpSignature(bytes)
  }

  return false
}

const sha256Hex = async (arrayBuffer: ArrayBuffer): Promise<string> => {
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer)
  const hashArray = new Uint8Array(hashBuffer)
  let hash = ''

  for (const byte of hashArray) {
    hash += byte.toString(16).padStart(2, '0')
  }

  return hash
}

const toDirectUrl = (request: Request, r2Key: string): string => {
  const origin = new URL(request.url).origin
  return `${origin}/i/${encodeURIComponent(r2Key)}`
}

const createUploadPayload = (
  id: string,
  directUrl: string,
): UploadResponse => ({
  id,
  directUrl,
  markdown: `![image](${directUrl})`,
  bbcode: `[img]${directUrl}[/img]`,
})

const isCopyFormat = (value: unknown): value is CopyFormat => {
  return value === 'direct' || value === 'markdown' || value === 'bbcode'
}

const isCopySource = (value: unknown): value is CopySource => {
  return value === 'uploader' || value === 'library' || value === 'detail'
}

const encodeBase64Url = (value: string): string => {
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

const decodeBase64Url = (value: string): string => {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const paddingLength = (4 - (normalized.length % 4)) % 4
  const padded = `${normalized}${'='.repeat(paddingLength)}`
  return atob(padded)
}

const encodePaginationCursor = (cursor: PaginationCursor): string => {
  return encodeBase64Url(JSON.stringify(cursor))
}

const decodePaginationCursor = (cursor: string): PaginationCursor | null => {
  try {
    const decoded = decodeBase64Url(cursor)
    const parsed = JSON.parse(decoded) as Partial<PaginationCursor>

    if (
      typeof parsed.createdAt !== 'string' ||
      parsed.createdAt.length === 0 ||
      typeof parsed.id !== 'string' ||
      parsed.id.length === 0
    ) {
      return null
    }

    return {
      createdAt: parsed.createdAt,
      id: parsed.id,
    }
  } catch {
    return null
  }
}

const safeDecodeURIComponent = (value: string): string | null => {
  try {
    return decodeURIComponent(value)
  } catch {
    return null
  }
}

const getRuntimeEnv = (): Record<string, unknown> | undefined => {
  const runtimeProcess = (
    globalThis as { process?: { env?: Record<string, unknown> } }
  ).process

  return runtimeProcess?.env
}

const getRuntimeEnvString = (key: string): string | null => {
  const value = getRuntimeEnv()?.[key]
  if (typeof value !== 'string') {
    return null
  }

  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

const parseEnvCsvSet = (key: string): Set<string> => {
  const value = getRuntimeEnvString(key)
  if (!value) {
    return new Set<string>()
  }

  return new Set(
    value
      .split(',')
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry) => entry.length > 0),
  )
}

const isAuthenticatedUserPaid = (user: AuthenticatedUser | null): boolean => {
  if (!user) {
    return false
  }

  const paidUserIds = parseEnvCsvSet('PAID_USER_IDS')
  if (paidUserIds.has(user.id.toLowerCase())) {
    return true
  }

  if (!user.email) {
    return false
  }

  const paidUserEmails = parseEnvCsvSet('PAID_USER_EMAILS')
  return paidUserEmails.has(user.email.toLowerCase())
}

const parseBatchSize = (value: FormDataEntryValue | null): number => {
  if (typeof value !== 'string') {
    return 1
  }

  const parsed = Number.parseInt(value, 10)
  if (!Number.isFinite(parsed) || parsed <= 1) {
    return 1
  }

  return parsed
}

const getAnonymousCookieSigningSecret = (): string | null => {
  return getRuntimeEnvString('BETTER_AUTH_SECRET')
}

const getCookieValue = (request: Request, name: string): string | null => {
  const cookieHeader = request.headers.get('cookie')
  if (!cookieHeader) {
    return null
  }

  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim()
    if (!trimmed) {
      continue
    }

    const separatorIndex = trimmed.indexOf('=')
    if (separatorIndex <= 0) {
      continue
    }

    const cookieName = trimmed.slice(0, separatorIndex)
    if (cookieName !== name) {
      continue
    }

    return trimmed.slice(separatorIndex + 1)
  }

  return null
}

const hasLikelyAuthSessionCookie = (request: Request): boolean => {
  const cookieHeader = request.headers.get('cookie')
  if (!cookieHeader) {
    return false
  }

  for (const part of cookieHeader.split(';')) {
    const trimmed = part.trim()
    if (!trimmed) {
      continue
    }

    const separatorIndex = trimmed.indexOf('=')
    if (separatorIndex <= 0) {
      continue
    }

    const cookieName = trimmed.slice(0, separatorIndex)
    if (AUTH_SESSION_COOKIE_NAMES.has(cookieName)) {
      return true
    }
  }

  return false
}

const timingSafeEqual = (a: string, b: string): boolean => {
  if (a.length !== b.length) {
    return false
  }

  let mismatch = 0
  for (let i = 0; i < a.length; i += 1) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }

  return mismatch === 0
}

const signAnonymousId = async (
  anonymousId: string,
  secret: string,
): Promise<string> => {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign'],
  )

  const signatureBuffer = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(anonymousId),
  )
  const signatureBytes = new Uint8Array(signatureBuffer)
  let binary = ''

  for (const byte of signatureBytes) {
    binary += String.fromCharCode(byte)
  }

  return encodeBase64Url(binary)
}

const createAnonymousCookieValue = async (
  anonymousId: string,
  signingSecret: string | null,
): Promise<string> => {
  if (!signingSecret) {
    return anonymousId
  }

  const signature = await signAnonymousId(anonymousId, signingSecret)
  return `${anonymousId}.${signature}`
}

const parseAnonymousIdFromCookie = async (
  request: Request,
  signingSecret: string | null,
): Promise<string | null> => {
  const rawCookieValue = getCookieValue(request, ANONYMOUS_COOKIE_NAME)
  if (!rawCookieValue) {
    return null
  }

  const decodedCookieValue =
    safeDecodeURIComponent(rawCookieValue) ?? rawCookieValue

  if (!signingSecret) {
    return ULID_REGEX.test(decodedCookieValue) ? decodedCookieValue : null
  }

  const separatorIndex = decodedCookieValue.indexOf('.')
  if (separatorIndex <= 0) {
    return null
  }

  const anonymousId = decodedCookieValue.slice(0, separatorIndex)
  const signature = decodedCookieValue.slice(separatorIndex + 1)

  if (!ULID_REGEX.test(anonymousId) || signature.length === 0) {
    return null
  }

  const expectedSignature = await signAnonymousId(anonymousId, signingSecret)
  return timingSafeEqual(signature, expectedSignature) ? anonymousId : null
}

const buildAnonymousCookieHeader = async (
  request: Request,
  anonymousId: string,
  signingSecret: string | null,
): Promise<string> => {
  const cookieValue = await createAnonymousCookieValue(
    anonymousId,
    signingSecret,
  )
  const encodedCookieValue = encodeURIComponent(cookieValue)
  const secureAttribute =
    new URL(request.url).protocol === 'https:' ? '; Secure' : ''

  return `${ANONYMOUS_COOKIE_NAME}=${encodedCookieValue}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${ANONYMOUS_COOKIE_MAX_AGE_SECONDS}${secureAttribute}`
}

const buildAnonymousCookieClearHeader = (request: Request): string => {
  const secureAttribute =
    new URL(request.url).protocol === 'https:' ? '; Secure' : ''

  return `${ANONYMOUS_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT${secureAttribute}`
}

const migrateAnonymousUploadsToUser = async (
  env: Env,
  anonymousId: string,
  userId: string,
): Promise<void> => {
  const nowIso = new Date().toISOString()

  await env.DB.prepare(
    `UPDATE uploads
     SET owner_user_id = ?,
         owner_anon_id = NULL,
         expires_at = NULL,
         updated_at = ?
     WHERE owner_anon_id = ?
       AND owner_user_id IS NULL`,
  )
    .bind(userId, nowIso, anonymousId)
    .run()
}

const resolveRequestIdentity = async (
  request: Request,
  env: Env,
  options: IdentityResolutionOptions,
): Promise<RequestIdentity> => {
  const signingSecret = getAnonymousCookieSigningSecret()
  const requestHasAuthCookie = hasLikelyAuthSessionCookie(request)
  let authenticatedUser: AuthenticatedUser | null = null
  let authSessionLookupFailed = false

  try {
    authenticatedUser = await getAuthenticatedUser(request)
  } catch (error) {
    if (requestHasAuthCookie) {
      authSessionLookupFailed = true
      console.warn(
        'Auth session lookup failed for authenticated request',
        error,
      )
    } else {
      console.warn('Auth session lookup failed; continuing as anonymous', error)
    }
  }

  if (authSessionLookupFailed) {
    return {
      userId: null,
      userEmail: null,
      isPaidUser: false,
      anonymousId: null,
      setCookieHeader: null,
      authSessionLookupFailed: true,
    }
  }

  const userId = authenticatedUser?.id ?? null
  const userEmail = authenticatedUser?.email ?? null
  const isPaidUser = isAuthenticatedUserPaid(authenticatedUser)
  let anonymousId = await parseAnonymousIdFromCookie(request, signingSecret)
  let setCookieHeader: string | null = null

  if (userId) {
    if (options.migrateAnonymousToUser && anonymousId) {
      await migrateAnonymousUploadsToUser(env, anonymousId, userId)
      anonymousId = null
      setCookieHeader = buildAnonymousCookieClearHeader(request)
    }

    return {
      userId,
      userEmail,
      isPaidUser,
      anonymousId,
      setCookieHeader,
      authSessionLookupFailed: false,
    }
  }

  if (!anonymousId && options.ensureAnonymousId) {
    anonymousId = createUlid()
    setCookieHeader = await buildAnonymousCookieHeader(
      request,
      anonymousId,
      signingSecret,
    )
  }

  return {
    userId: null,
    userEmail: null,
    isPaidUser: false,
    anonymousId,
    setCookieHeader,
    authSessionLookupFailed: false,
  }
}

const resolveOwnerScope = (identity: RequestIdentity): OwnerScope | null => {
  const ownerId = identity.userId ?? identity.anonymousId
  if (!ownerId) {
    return null
  }

  return {
    ownerField: identity.userId ? 'owner_user_id' : 'owner_anon_id',
    ownerId,
  }
}

const getRequestIpAddress = (request: Request): string | null => {
  const directIp = request.headers.get('cf-connecting-ip')?.trim()
  if (directIp) {
    return directIp
  }

  const forwarded = request.headers.get('x-forwarded-for')
  if (!forwarded) {
    return null
  }

  const firstIp = forwarded
    .split(',')
    .map((entry) => entry.trim())
    .find((entry) => entry.length > 0)

  return firstIp ?? null
}

const getRateLimitScopeId = (
  scope: RateLimitScope,
  request: Request,
  identity: RequestIdentity,
): string | null => {
  if (scope === 'user') {
    return identity.userId
  }

  if (scope === 'anonymous') {
    return identity.anonymousId
  }

  return getRequestIpAddress(request)
}

const incrementRateLimitCounter = async (
  env: Env,
  operation: RateLimitedOperation,
  rule: RateLimitRule,
  scopeId: string,
): Promise<{
  count: number
  retryAfterSeconds: number
} | null> => {
  const now = Date.now()
  const windowStartedAt = Math.floor(now / rule.windowMs) * rule.windowMs
  const entryId = `${operation}:${rule.scope}:${scopeId}:${windowStartedAt}`
  const nowIso = new Date(now).toISOString()

  try {
    await env.DB.prepare(
      `INSERT INTO request_rate_limits (
         id,
         operation,
         scope,
         scope_id,
         window_started_at,
         request_count,
         created_at,
         updated_at
       ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         request_count = request_count + 1,
         updated_at = excluded.updated_at`,
    )
      .bind(
        entryId,
        operation,
        rule.scope,
        scopeId,
        windowStartedAt,
        nowIso,
        nowIso,
      )
      .run()

    const counterRow = await env.DB.prepare(
      `SELECT request_count
       FROM request_rate_limits
       WHERE id = ?
       LIMIT 1`,
    )
      .bind(entryId)
      .first<{ request_count: number | string }>()

    const rawCount = counterRow?.request_count ?? 0
    const count = typeof rawCount === 'number' ? rawCount : Number(rawCount)

    if (!Number.isFinite(count)) {
      return null
    }

    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((windowStartedAt + rule.windowMs - now) / 1000),
    )

    return {
      count,
      retryAfterSeconds,
    }
  } catch (error) {
    console.error('Rate limit counter update failed; allowing request', error)
    return null
  }
}

const enforceRateLimits = async (
  request: Request,
  env: Env,
  identity: RequestIdentity,
  operation: RateLimitedOperation,
): Promise<Response | null> => {
  for (const rule of RATE_LIMIT_RULES[operation]) {
    const scopeId = getRateLimitScopeId(rule.scope, request, identity)
    if (!scopeId) {
      continue
    }

    const counter = await incrementRateLimitCounter(
      env,
      operation,
      rule,
      scopeId,
    )
    if (!counter) {
      continue
    }

    if (counter.count <= rule.maxRequests) {
      continue
    }

    return respondJson(
      {
        error: 'Too many requests. Please retry shortly.',
        retryAfterSeconds: counter.retryAfterSeconds,
      },
      429,
      {
        'retry-after': String(counter.retryAfterSeconds),
      },
    )
  }

  return null
}

const getTelemetryFailureReason = (statusCode: number): string | null => {
  if (statusCode < 400) {
    return null
  }

  if (statusCode >= 500) {
    return 'server_error'
  }

  return 'client_error'
}

const writeRequestTelemetryEvent = async (
  env: Env,
  requestType: RequestTelemetryType,
  requestPath: string,
  statusCode: number,
  latencyMs: number,
): Promise<void> => {
  const nowIso = new Date().toISOString()
  const failureReason = getTelemetryFailureReason(statusCode)
  const normalizedLatencyMs = Math.max(0, Math.round(latencyMs))

  try {
    await env.DB.prepare(
      `INSERT INTO request_telemetry_events (
         id,
         request_type,
         request_path,
         status_code,
         latency_ms,
         failed,
         failure_reason,
         created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        createUlid(),
        requestType,
        requestPath,
        statusCode,
        normalizedLatencyMs,
        statusCode >= 400 ? 1 : 0,
        failureReason,
        nowIso,
      )
      .run()
  } catch (error) {
    console.error('Request telemetry write failed', error)
  }
}

const runWithRequestTelemetry = async (
  request: Request,
  env: Env,
  context: WorkerExecutionContext,
  requestType: RequestTelemetryType,
  run: () => Promise<Response>,
): Promise<Response> => {
  const startedAt = Date.now()

  try {
    const response = await run()
    context.waitUntil(
      writeRequestTelemetryEvent(
        env,
        requestType,
        new URL(request.url).pathname,
        response.status,
        Date.now() - startedAt,
      ),
    )
    return response
  } catch (error) {
    context.waitUntil(
      writeRequestTelemetryEvent(
        env,
        requestType,
        new URL(request.url).pathname,
        500,
        Date.now() - startedAt,
      ),
    )
    throw error
  }
}

const deleteUploadAssets = async (
  env: Env,
  upload: CleanupUploadRow,
): Promise<boolean> => {
  const keysToDelete = Array.from(
    new Set(
      [upload.r2_key, upload.thumb_r2_key, upload.webp_r2_key].filter(
        (value): value is string => Boolean(value),
      ),
    ),
  )

  try {
    await Promise.all(keysToDelete.map((key) => env.BUCKET.delete(key)))
    return true
  } catch (error) {
    console.error('Object cleanup failed; upload record retained for retry', {
      uploadId: upload.id,
      error,
    })
    return false
  }
}

const hardDeleteUpload = async (env: Env, uploadId: string): Promise<void> => {
  await env.DB.prepare(
    `DELETE FROM uploads
     WHERE id = ?`,
  )
    .bind(uploadId)
    .run()
}

const cleanupUploadsByQuery = async (
  env: Env,
  query: string,
  bindValues: Array<string | number>,
): Promise<number> => {
  const result = await env.DB.prepare(query)
    .bind(...bindValues)
    .all<CleanupUploadRow>()
  const rows = result.results ?? []

  if (rows.length === 0) {
    return 0
  }

  let deletedCount = 0

  for (const row of rows) {
    const didDeleteAssets = await deleteUploadAssets(env, row)
    if (!didDeleteAssets) {
      continue
    }

    try {
      await hardDeleteUpload(env, row.id)
      deletedCount += 1
    } catch (error) {
      console.error('Upload row hard delete failed after object cleanup', {
        uploadId: row.id,
        error,
      })
    }
  }

  return deletedCount
}

const cleanupExpiredAnonymousUploads = async (env: Env): Promise<number> => {
  const nowIso = new Date().toISOString()
  let deletedCount = 0

  for (let index = 0; index < MAX_CLEANUP_BATCHES_PER_RUN; index += 1) {
    const batchDeleted = await cleanupUploadsByQuery(
      env,
      `SELECT id, r2_key, thumb_r2_key, webp_r2_key
       FROM uploads
       WHERE owner_user_id IS NULL
         AND owner_anon_id IS NOT NULL
         AND expires_at IS NOT NULL
         AND expires_at <= ?
         AND deleted_at IS NULL
       ORDER BY expires_at ASC
       LIMIT ?`,
      [nowIso, CLEANUP_BATCH_SIZE],
    )

    deletedCount += batchDeleted

    if (batchDeleted < CLEANUP_BATCH_SIZE) {
      break
    }
  }

  return deletedCount
}

const cleanupSoftDeletedUploads = async (env: Env): Promise<number> => {
  const cutoffIso = new Date(
    Date.now() - SOFT_DELETE_GRACE_PERIOD_DAYS * 24 * 60 * 60 * 1000,
  ).toISOString()
  let deletedCount = 0

  for (let index = 0; index < MAX_CLEANUP_BATCHES_PER_RUN; index += 1) {
    const batchDeleted = await cleanupUploadsByQuery(
      env,
      `SELECT id, r2_key, thumb_r2_key, webp_r2_key
       FROM uploads
       WHERE deleted_at IS NOT NULL
         AND deleted_at <= ?
       ORDER BY deleted_at ASC
       LIMIT ?`,
      [cutoffIso, CLEANUP_BATCH_SIZE],
    )

    deletedCount += batchDeleted

    if (batchDeleted < CLEANUP_BATCH_SIZE) {
      break
    }
  }

  return deletedCount
}

const cleanupStaleRateLimitRows = async (env: Env): Promise<number> => {
  const cutoffMs = Date.now() - RATE_LIMIT_RETENTION_HOURS * 60 * 60 * 1000

  const countResult = await env.DB.prepare(
    `SELECT COUNT(*) AS total
     FROM request_rate_limits
     WHERE window_started_at < ?`,
  )
    .bind(cutoffMs)
    .first<{ total: number | string }>()

  const rawTotal = countResult?.total ?? 0
  const total = typeof rawTotal === 'number' ? rawTotal : Number(rawTotal)

  if (!Number.isFinite(total) || total <= 0) {
    return 0
  }

  await env.DB.prepare(
    `DELETE FROM request_rate_limits
     WHERE window_started_at < ?`,
  )
    .bind(cutoffMs)
    .run()

  return total
}

const cleanupOldTelemetryRows = async (env: Env): Promise<number> => {
  const cutoffIso = new Date(
    Date.now() - TELEMETRY_RETENTION_DAYS * 24 * 60 * 60 * 1000,
  ).toISOString()

  const countResult = await env.DB.prepare(
    `SELECT COUNT(*) AS total
     FROM request_telemetry_events
     WHERE created_at < ?`,
  )
    .bind(cutoffIso)
    .first<{ total: number | string }>()

  const rawTotal = countResult?.total ?? 0
  const total = typeof rawTotal === 'number' ? rawTotal : Number(rawTotal)

  if (!Number.isFinite(total) || total <= 0) {
    return 0
  }

  await env.DB.prepare(
    `DELETE FROM request_telemetry_events
     WHERE created_at < ?`,
  )
    .bind(cutoffIso)
    .run()

  return total
}

const runScheduledMaintenance = async (env: Env): Promise<void> => {
  const startedAt = Date.now()

  try {
    const expiredAnonymousDeleted = await cleanupExpiredAnonymousUploads(env)
    const softDeletedRemoved = await cleanupSoftDeletedUploads(env)
    const staleRateLimitRowsRemoved = await cleanupStaleRateLimitRows(env)
    const oldTelemetryRowsRemoved = await cleanupOldTelemetryRows(env)

    console.info('Scheduled cleanup completed', {
      expiredAnonymousDeleted,
      softDeletedRemoved,
      staleRateLimitRowsRemoved,
      oldTelemetryRowsRemoved,
      durationMs: Date.now() - startedAt,
    })
  } catch (error) {
    console.error('Scheduled cleanup failed', error)
  }
}

const withTimeout = async <T>(
  promise: Promise<T>,
  timeoutMs: number,
  timeoutMessage: string,
): Promise<T> => {
  let timeoutId: ReturnType<typeof setTimeout> | undefined

  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(timeoutMessage))
    }, timeoutMs)
  })

  try {
    return await Promise.race([promise, timeoutPromise])
  } finally {
    if (timeoutId !== undefined) {
      clearTimeout(timeoutId)
    }
  }
}

const getAuthenticatedUser = async (
  request: Request,
): Promise<AuthenticatedUser | null> => {
  for (let attempt = 1; attempt <= SESSION_LOOKUP_MAX_ATTEMPTS; attempt += 1) {
    try {
      const session = await withTimeout(
        auth.api.getSession({
          headers: request.headers,
        }),
        SESSION_LOOKUP_TIMEOUT_MS,
        AUTH_SESSION_LOOKUP_TIMEOUT_MESSAGE,
      )

      const user = (
        session as { user?: { id?: unknown; email?: unknown } } | null
      )?.user

      if (!user || typeof user.id !== 'string' || user.id.length === 0) {
        return null
      }

      return {
        id: user.id,
        email: typeof user.email === 'string' ? user.email : null,
      }
    } catch (error) {
      if (attempt >= SESSION_LOOKUP_MAX_ATTEMPTS) {
        throw error
      }
    }
  }

  return null
}

const handleGetMyEntitlementsRequest = async (
  request: Request,
  env: Env,
): Promise<Response> => {
  const identity = await resolveRequestIdentity(request, env, {
    ensureAnonymousId: false,
    migrateAnonymousToUser: true,
  })

  if (identity.authSessionLookupFailed) {
    return respondAuthSessionUnavailable(identity.setCookieHeader)
  }

  const libraryLimit = identity.isPaidUser
    ? MAX_PAID_USER_UPLOADS
    : identity.userId
      ? MAX_USER_UPLOADS
      : MAX_ANONYMOUS_UPLOADS

  let libraryUsage = 0

  if (identity.userId) {
    const result = await env.DB.prepare(
      `SELECT COUNT(*) AS total
       FROM uploads
       WHERE owner_user_id = ?
         AND deleted_at IS NULL`,
    )
      .bind(identity.userId)
      .first<{ total: number | string }>()

    const raw = result?.total ?? 0
    libraryUsage = typeof raw === 'number' ? raw : Number(raw)
    if (!Number.isFinite(libraryUsage)) libraryUsage = 0
  } else if (identity.anonymousId) {
    const result = await env.DB.prepare(
      `SELECT COUNT(*) AS total
       FROM uploads
       WHERE owner_anon_id = ?
         AND deleted_at IS NULL`,
    )
      .bind(identity.anonymousId)
      .first<{ total: number | string }>()

    const raw = result?.total ?? 0
    libraryUsage = typeof raw === 'number' ? raw : Number(raw)
    if (!Number.isFinite(libraryUsage)) libraryUsage = 0
  }

  return withSetCookieHeader(
    respondJson({
      isAuthenticated: Boolean(identity.userId),
      isPaid: identity.isPaidUser,
      multiFileUploadEnabled: Boolean(identity.userId && identity.isPaidUser),
      libraryLimit,
      libraryUsage,
    }),
    identity.setCookieHeader,
  )
}

const handleCopyTrackingRequest = async (
  request: Request,
  env: Env,
  uploadId: string,
): Promise<Response> => {
  const identity = await resolveRequestIdentity(request, env, {
    ensureAnonymousId: false,
    migrateAnonymousToUser: true,
  })

  if (identity.authSessionLookupFailed) {
    return respondAuthSessionUnavailable(identity.setCookieHeader)
  }

  const respond = (body: Record<string, unknown>, status: number): Response => {
    return withSetCookieHeader(
      respondJson(body, status),
      identity.setCookieHeader,
    )
  }

  if (!identity.userId) {
    return withSetCookieHeader(
      new Response(null, { status: 204 }),
      identity.setCookieHeader,
    )
  }

  const rateLimitResponse = await enforceRateLimits(
    request,
    env,
    identity,
    'copy',
  )
  if (rateLimitResponse) {
    return withSetCookieHeader(rateLimitResponse, identity.setCookieHeader)
  }

  let body: unknown

  try {
    body = await request.json()
  } catch {
    return respond(
      {
        error: 'Expected a JSON request body.',
      },
      400,
    )
  }

  if (!body || typeof body !== 'object') {
    return respond(
      {
        error: 'Expected a JSON object body.',
      },
      400,
    )
  }

  const payload = body as {
    format?: unknown
    source?: unknown
  }

  if (!isCopyFormat(payload.format)) {
    return respond(
      {
        error: "Invalid format. Allowed: 'direct', 'markdown', 'bbcode'.",
      },
      400,
    )
  }

  if (!isCopySource(payload.source)) {
    return respond(
      {
        error: "Invalid source. Allowed: 'uploader', 'library', 'detail'.",
      },
      400,
    )
  }

  const upload = await env.DB.prepare(
    `SELECT id, owner_user_id
     FROM uploads
     WHERE id = ?
        AND deleted_at IS NULL
     LIMIT 1`,
  )
    .bind(uploadId)
    .first<{ id: string; owner_user_id: string | null }>()

  if (!upload) {
    return respond(
      {
        error: 'Upload not found.',
      },
      404,
    )
  }

  if (upload.owner_user_id !== identity.userId) {
    return respond(
      {
        error: 'Not authorized to track copy activity for this upload.',
      },
      403,
    )
  }

  const nowIso = new Date().toISOString()

  try {
    await env.DB.prepare(
      `UPDATE uploads
       SET copy_count = copy_count + 1,
           updated_at = ?
       WHERE id = ?
         AND deleted_at IS NULL`,
    )
      .bind(nowIso, uploadId)
      .run()

    await env.DB.prepare(
      `INSERT INTO upload_copy_events (
         id,
         upload_id,
         actor_user_id,
         copied_format,
         copied_at,
         source
       ) VALUES (?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        createUlid(),
        uploadId,
        identity.userId,
        payload.format,
        nowIso,
        payload.source,
      )
      .run()
  } catch (error) {
    console.error('Copy tracking write failed', error)
    return respond(
      {
        error: 'Failed to track copy event.',
      },
      500,
    )
  }

  return withSetCookieHeader(
    new Response(null, { status: 204 }),
    identity.setCookieHeader,
  )
}

const toUploadListItem = (
  request: Request,
  row: UploadQueryRow,
): UploadListItem => {
  const directUrl = row.public_url || toDirectUrl(request, row.r2_key)

  return {
    id: row.id,
    directUrl,
    markdown: `![image](${directUrl})`,
    bbcode: `[img]${directUrl}[/img]`,
    thumbUrl: row.thumb_r2_key
      ? toDirectUrl(request, row.thumb_r2_key)
      : directUrl,
    webpUrl: row.webp_r2_key ? toDirectUrl(request, row.webp_r2_key) : null,
    mimeType: row.mime_type,
    sizeBytes: row.size_bytes,
    width: row.width,
    height: row.height,
    copyCount: row.copy_count,
    optimizationStatus: row.optimization_status,
    createdAt: row.created_at,
  }
}

const handleGetMyUploadsRequest = async (
  request: Request,
  env: Env,
): Promise<Response> => {
  const identity = await resolveRequestIdentity(request, env, {
    ensureAnonymousId: true,
    migrateAnonymousToUser: true,
  })

  if (identity.authSessionLookupFailed) {
    return respondAuthSessionUnavailable(identity.setCookieHeader)
  }

  const ownerScope = resolveOwnerScope(identity)

  if (!ownerScope) {
    return withSetCookieHeader(
      respondJson(
        {
          error: 'Failed to resolve library owner identity.',
        },
        500,
      ),
      identity.setCookieHeader,
    )
  }

  const cursorValue = new URL(request.url).searchParams.get('cursor')
  const cursor = cursorValue ? decodePaginationCursor(cursorValue) : null

  if (cursorValue && !cursor) {
    return withSetCookieHeader(
      respondJson(
        {
          error: 'Invalid pagination cursor.',
        },
        400,
      ),
      identity.setCookieHeader,
    )
  }

  const limit = LIBRARY_PAGE_SIZE + 1
  let rows: Array<UploadQueryRow> = []

  if (cursor) {
    const result = await env.DB.prepare(
      `SELECT
         id,
         r2_key,
         public_url,
         mime_type,
         size_bytes,
         width,
         height,
         copy_count,
         created_at,
         thumb_r2_key,
         webp_r2_key,
         webp_size_bytes,
         optimization_status
        FROM uploads
       WHERE ${ownerScope.ownerField} = ?
         AND deleted_at IS NULL
         AND (
           created_at < ?
           OR (created_at = ? AND id < ?)
         )
       ORDER BY created_at DESC, id DESC
       LIMIT ?`,
    )
      .bind(
        ownerScope.ownerId,
        cursor.createdAt,
        cursor.createdAt,
        cursor.id,
        limit,
      )
      .all<UploadQueryRow>()

    rows = result.results ?? []
  } else {
    const result = await env.DB.prepare(
      `SELECT
         id,
         r2_key,
         public_url,
         mime_type,
         size_bytes,
         width,
         height,
         copy_count,
         created_at,
         thumb_r2_key,
         webp_r2_key,
         webp_size_bytes,
         optimization_status
        FROM uploads
       WHERE ${ownerScope.ownerField} = ?
         AND deleted_at IS NULL
       ORDER BY created_at DESC, id DESC
       LIMIT ?`,
    )
      .bind(ownerScope.ownerId, limit)
      .all<UploadQueryRow>()

    rows = result.results ?? []
  }

  const hasMore = rows.length > LIBRARY_PAGE_SIZE
  const pageRows = hasMore ? rows.slice(0, LIBRARY_PAGE_SIZE) : rows
  const items = pageRows.map((row) => toUploadListItem(request, row))
  const lastItem = pageRows[pageRows.length - 1]
  const nextCursor = hasMore
    ? encodePaginationCursor({
        createdAt: lastItem.created_at,
        id: lastItem.id,
      })
    : null

  return withSetCookieHeader(
    respondJson({
      items,
      nextCursor,
      mode: identity.userId ? 'user' : 'anonymous',
    }),
    identity.setCookieHeader,
  )
}

const handleDeleteMyUploadRequest = async (
  request: Request,
  env: Env,
  uploadId: string,
): Promise<Response> => {
  const identity = await resolveRequestIdentity(request, env, {
    ensureAnonymousId: true,
    migrateAnonymousToUser: true,
  })

  if (identity.authSessionLookupFailed) {
    return respondAuthSessionUnavailable(identity.setCookieHeader)
  }

  const ownerScope = resolveOwnerScope(identity)

  if (!ownerScope) {
    return withSetCookieHeader(
      respondJson(
        {
          error: 'Failed to resolve library owner identity.',
        },
        500,
      ),
      identity.setCookieHeader,
    )
  }

  const rateLimitResponse = await enforceRateLimits(
    request,
    env,
    identity,
    'delete',
  )
  if (rateLimitResponse) {
    return withSetCookieHeader(rateLimitResponse, identity.setCookieHeader)
  }

  const existingUpload = await env.DB.prepare(
    `SELECT id
      FROM uploads
      WHERE id = ?
        AND ${ownerScope.ownerField} = ?
        AND deleted_at IS NULL
      LIMIT 1`,
  )
    .bind(uploadId, ownerScope.ownerId)
    .first<{ id: string }>()

  if (!existingUpload) {
    return withSetCookieHeader(
      respondJson(
        {
          error: 'Upload not found.',
        },
        404,
      ),
      identity.setCookieHeader,
    )
  }

  const nowIso = new Date().toISOString()

  try {
    await env.DB.prepare(
      `UPDATE uploads
       SET deleted_at = ?,
           updated_at = ?
       WHERE id = ?
         AND ${ownerScope.ownerField} = ?
         AND deleted_at IS NULL`,
    )
      .bind(nowIso, nowIso, uploadId, ownerScope.ownerId)
      .run()
  } catch (error) {
    console.error('Soft delete update failed', error)
    return withSetCookieHeader(
      respondJson(
        {
          error: 'Failed to delete upload.',
        },
        500,
      ),
      identity.setCookieHeader,
    )
  }

  return withSetCookieHeader(
    new Response(null, { status: 204 }),
    identity.setCookieHeader,
  )
}

const handleUploadRequest = async (
  request: Request,
  env: Env,
): Promise<Response> => {
  const contentType = request.headers.get('content-type') ?? ''
  if (!contentType.includes('multipart/form-data')) {
    return respondJson(
      {
        error: 'Expected multipart/form-data upload.',
      },
      415,
    )
  }

  const identity = await resolveRequestIdentity(request, env, {
    ensureAnonymousId: true,
    migrateAnonymousToUser: true,
  })

  if (identity.authSessionLookupFailed) {
    return respondAuthSessionUnavailable(identity.setCookieHeader)
  }

  const respondWithIdentity = (
    body: Record<string, unknown>,
    status: number,
  ): Response => {
    return withSetCookieHeader(
      respondJson(body, status),
      identity.setCookieHeader,
    )
  }

  const rateLimitResponse = await enforceRateLimits(
    request,
    env,
    identity,
    'upload',
  )
  if (rateLimitResponse) {
    return withSetCookieHeader(rateLimitResponse, identity.setCookieHeader)
  }

  let formData: FormData

  try {
    formData = await request.formData()
  } catch {
    return respondWithIdentity(
      {
        error: 'Failed to parse multipart upload payload.',
      },
      400,
    )
  }

  const batchSize = parseBatchSize(formData.get(PAID_MULTI_UPLOAD_BATCH_FIELD))
  const fileEntry = formData.get('file')

  if (!(fileEntry instanceof File)) {
    return respondWithIdentity(
      {
        error: "Missing file field. Send a multipart field named 'file'.",
      },
      400,
    )
  }

  if (fileEntry.size <= 0) {
    return respondWithIdentity(
      {
        error: 'Uploaded file is empty.',
      },
      400,
    )
  }

  if (fileEntry.size > MAX_UPLOAD_SIZE_BYTES) {
    return respondWithIdentity(
      {
        error: 'File too large. Maximum upload size is 15 MB.',
      },
      413,
    )
  }

  const mimeType = fileEntry.type.toLowerCase()
  const expectedExtension = MIME_TO_EXTENSION[mimeType]

  if (!expectedExtension) {
    return respondWithIdentity(
      {
        error: 'Unsupported image type. Allowed: PNG, JPEG, GIF, WEBP.',
      },
      400,
    )
  }

  const extension = getFileExtension(fileEntry.name)
  if (extension) {
    const extensionMimeType = EXTENSION_TO_MIME[extension]
    if (!extensionMimeType || extensionMimeType !== mimeType) {
      return respondWithIdentity(
        {
          error: 'File extension does not match MIME type.',
        },
        400,
      )
    }
  }

  const ownerUserId = identity.userId
  const ownerUserEmail = identity.userEmail
  const ownerAnonymousId = ownerUserId ? null : identity.anonymousId

  const fileBuffer = await fileEntry.arrayBuffer()
  const fileBytes = new Uint8Array(fileBuffer)

  if (!hasValidImageSignature(fileBytes, mimeType)) {
    return respondWithIdentity(
      {
        error: 'File content signature is not a valid image.',
      },
      400,
    )
  }

  if (batchSize > 1) {
    if (!ownerUserId) {
      return respondWithIdentity(
        {
          error:
            'Multi-file upload is available for paid accounts. Sign in and upgrade to continue.',
        },
        403,
      )
    }

    if (!identity.isPaidUser) {
      return respondWithIdentity(
        {
          error: `Multi-file upload requires a paid plan. ${ownerUserEmail ? `Current account: ${ownerUserEmail}. ` : ''}Upgrade to continue.`,
        },
        403,
      )
    }
  }

  if (ownerUserId) {
    const maxUploads = identity.isPaidUser
      ? MAX_PAID_USER_UPLOADS
      : MAX_USER_UPLOADS

    const usageResult = await env.DB.prepare(
      `SELECT COUNT(*) AS total
       FROM uploads
       WHERE owner_user_id = ?
         AND deleted_at IS NULL`,
    )
      .bind(ownerUserId)
      .first<{ total: number | string }>()

    const rawTotal = usageResult?.total ?? 0
    const totalUploads =
      typeof rawTotal === 'number' ? rawTotal : Number(rawTotal)

    if (Number.isFinite(totalUploads) && totalUploads >= maxUploads) {
      const upgradeHint = identity.isPaidUser
        ? ''
        : ' Upgrade to a paid plan for up to 10,000.'
      return respondWithIdentity(
        {
          error: `Library limit reached (${maxUploads.toLocaleString()} images).${upgradeHint}`,
        },
        403,
      )
    }
  } else {
    if (!ownerAnonymousId) {
      return respondWithIdentity(
        {
          error: 'Failed to resolve anonymous upload identity.',
        },
        500,
      )
    }

    const usageResult = await env.DB.prepare(
      `SELECT COUNT(*) AS total
       FROM uploads
       WHERE owner_anon_id = ?
         AND deleted_at IS NULL`,
    )
      .bind(ownerAnonymousId)
      .first<{ total: number | string }>()

    const rawTotal = usageResult?.total ?? 0
    const totalUploads =
      typeof rawTotal === 'number' ? rawTotal : Number(rawTotal)

    if (
      Number.isFinite(totalUploads) &&
      totalUploads >= MAX_ANONYMOUS_UPLOADS
    ) {
      return respondWithIdentity(
        {
          error: `Guest library limit reached (${MAX_ANONYMOUS_UPLOADS} images). Sign in to store more.`,
        },
        403,
      )
    }
  }

  const id = createUlid()
  const r2Key = `${id}/original.${expectedExtension}`
  const directUrl = toDirectUrl(request, r2Key)
  const nowIso = new Date().toISOString()
  const expiresAtIso = ownerUserId
    ? null
    : new Date(
        Date.now() + ANONYMOUS_UPLOAD_EXPIRY_DAYS * 24 * 60 * 60 * 1000,
      ).toISOString()
  const sha256 = await sha256Hex(fileBuffer)

  try {
    await env.BUCKET.put(r2Key, fileBuffer, {
      httpMetadata: {
        contentType: mimeType,
      },
    })
  } catch (error) {
    console.error('Upload object storage write failed', error)
    return respondWithIdentity(
      {
        error: 'Failed to store upload in object storage.',
      },
      500,
    )
  }

  try {
    await env.DB.prepare(
      `INSERT INTO uploads (
        id,
        owner_user_id,
        owner_anon_id,
        expires_at,
        r2_key,
        public_url,
        mime_type,
        size_bytes,
        optimization_status,
        sha256,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`,
    )
      .bind(
        id,
        ownerUserId,
        ownerAnonymousId,
        expiresAtIso,
        r2Key,
        directUrl,
        mimeType,
        fileEntry.size,
        sha256,
        nowIso,
        nowIso,
      )
      .run()
  } catch (error) {
    try {
      await env.BUCKET.delete(r2Key)
    } catch (cleanupError) {
      console.error('Upload object cleanup failed', cleanupError)
    }
    console.error('Upload metadata insert failed', error)
    return respondWithIdentity(
      {
        error: 'Failed to persist upload metadata.',
      },
      500,
    )
  }

  return withSetCookieHeader(
    respondJson(createUploadPayload(id, directUrl), 201),
    identity.setCookieHeader,
  )
}

const handlePublicImageRequest = async (
  request: Request,
  env: Env,
): Promise<Response> => {
  const pathname = new URL(request.url).pathname
  const encodedKey = pathname.slice(3)

  if (!encodedKey) {
    return new Response('Not Found', { status: 404 })
  }

  const key = decodeURIComponent(encodedKey)
  const uploadRecord = await env.DB.prepare(
    `SELECT deleted_at
     FROM uploads
     WHERE r2_key = ?
     LIMIT 1`,
  )
    .bind(key)
    .first<{ deleted_at: string | null }>()

  if (!uploadRecord || uploadRecord.deleted_at !== null) {
    return new Response('Not Found', { status: 404 })
  }

  const object = await env.BUCKET.get(key)

  if (!object) {
    return new Response('Not Found', { status: 404 })
  }

  const headers = new Headers()
  object.writeHttpMetadata(headers)
  headers.set('etag', object.httpEtag)
  headers.set('cache-control', 'public, max-age=31536000, immutable')

  if (request.method === 'HEAD') {
    return new Response(null, { headers })
  }

  return new Response(object.body, { headers })
}

export default {
  async fetch(request: Request, env: Env, context: WorkerExecutionContext) {
    const url = new URL(request.url)

    const copyRouteMatch = url.pathname.match(/^\/api\/uploads\/([^/]+)\/copy$/)
    if (copyRouteMatch) {
      if (request.method !== 'POST') {
        return methodNotAllowed('POST')
      }

      const encodedUploadId = copyRouteMatch[1]
      const uploadId = safeDecodeURIComponent(encodedUploadId)

      if (!uploadId) {
        return respondJson(
          {
            error: 'Invalid upload id in URL path.',
          },
          400,
        )
      }

      return runWithRequestTelemetry(
        request,
        env,
        context,
        'copy',
        async () => {
          try {
            return await handleCopyTrackingRequest(request, env, uploadId)
          } catch (error) {
            console.error('Unhandled copy tracking request error', error)
            return respondJson(
              {
                error: 'Copy tracking failed unexpectedly. Please retry.',
              },
              500,
            )
          }
        },
      )
    }

    if (url.pathname === '/api/me/uploads') {
      if (request.method !== 'GET') {
        return methodNotAllowed('GET')
      }

      try {
        return await handleGetMyUploadsRequest(request, env)
      } catch (error) {
        console.error('Unhandled my uploads request error', error)
        return respondJson(
          {
            error: 'Failed to load uploads unexpectedly. Please retry.',
          },
          500,
        )
      }
    }

    if (url.pathname === '/api/me/entitlements') {
      if (request.method !== 'GET') {
        return methodNotAllowed('GET')
      }

      try {
        return await handleGetMyEntitlementsRequest(request, env)
      } catch (error) {
        console.error('Unhandled entitlements request error', error)
        return respondJson(
          {
            error: 'Failed to load entitlements unexpectedly. Please retry.',
          },
          500,
        )
      }
    }

    const deleteUploadRouteMatch = url.pathname.match(
      /^\/api\/me\/uploads\/([^/]+)$/,
    )
    if (deleteUploadRouteMatch) {
      if (request.method !== 'DELETE') {
        return methodNotAllowed('DELETE')
      }

      const encodedUploadId = deleteUploadRouteMatch[1]
      const uploadId = safeDecodeURIComponent(encodedUploadId)

      if (!uploadId) {
        return respondJson(
          {
            error: 'Invalid upload id in URL path.',
          },
          400,
        )
      }

      try {
        return await handleDeleteMyUploadRequest(request, env, uploadId)
      } catch (error) {
        console.error('Unhandled delete upload request error', error)
        return respondJson(
          {
            error: 'Failed to delete upload unexpectedly. Please retry.',
          },
          500,
        )
      }
    }

    if (url.pathname === '/api/uploads') {
      if (request.method !== 'POST') {
        return methodNotAllowed('POST')
      }

      return runWithRequestTelemetry(
        request,
        env,
        context,
        'upload',
        async () => {
          try {
            return await handleUploadRequest(request, env)
          } catch (error) {
            console.error('Unhandled upload request error', error)
            return respondJson(
              {
                error: 'Upload failed unexpectedly. Please retry.',
              },
              500,
            )
          }
        },
      )
    }

    if (url.pathname.startsWith('/i/')) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return methodNotAllowed('GET, HEAD')
      }
      return handlePublicImageRequest(request, env)
    }

    return handler.fetch(request)
  },
  scheduled(
    _controller: WorkerScheduledController,
    env: Env,
    context: WorkerExecutionContext,
  ) {
    context.waitUntil(runScheduledMaintenance(env))
  },
} satisfies WorkerHandler
