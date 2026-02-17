import handler from '@tanstack/solid-start/server-entry'
import { auth } from '../lib/auth'

const MAX_UPLOAD_SIZE_BYTES = 15 * 1024 * 1024
const MAX_ANONYMOUS_UPLOADS = 50
const ANONYMOUS_UPLOAD_EXPIRY_DAYS = 30
const SESSION_LOOKUP_TIMEOUT_MS = 1_500
const LIBRARY_PAGE_SIZE = 30
const ANONYMOUS_COOKIE_NAME = 'piccy_anon_id'
const ANONYMOUS_COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 365
const ULID_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const ULID_REGEX = /^[0-9A-HJKMNP-TV-Z]{26}$/

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
  fetch: (request: Request, env: Env) => Promise<Response>
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
  anonymousId: string | null
  setCookieHeader: string | null
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
  const userId = await getAuthenticatedUserId(request)
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
      anonymousId,
      setCookieHeader,
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
    anonymousId,
    setCookieHeader,
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

const getAuthenticatedUserId = async (
  request: Request,
): Promise<string | null> => {
  try {
    const session = await withTimeout(
      auth.api.getSession({
        headers: request.headers,
      }),
      SESSION_LOOKUP_TIMEOUT_MS,
      'Auth session lookup timed out',
    )

    return session?.user.id ?? null
  } catch (error) {
    console.warn('Auth session lookup failed; continuing as anonymous', error)
    return null
  }
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
    `SELECT id
     FROM uploads
     WHERE id = ?
       AND deleted_at IS NULL
     LIMIT 1`,
  )
    .bind(uploadId)
    .first<{ id: string }>()

  if (!upload) {
    return respond(
      {
        error: 'Upload not found.',
      },
      404,
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

  const ownerField = identity.userId ? 'owner_user_id' : 'owner_anon_id'
  const ownerId = identity.userId ?? identity.anonymousId

  if (!ownerId) {
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
       WHERE ${ownerField} = ?
         AND deleted_at IS NULL
         AND (
           created_at < ?
           OR (created_at = ? AND id < ?)
         )
       ORDER BY created_at DESC, id DESC
       LIMIT ?`,
    )
      .bind(ownerId, cursor.createdAt, cursor.createdAt, cursor.id, limit)
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
       WHERE ${ownerField} = ?
         AND deleted_at IS NULL
       ORDER BY created_at DESC, id DESC
       LIMIT ?`,
    )
      .bind(ownerId, limit)
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

  const ownerField = identity.userId ? 'owner_user_id' : 'owner_anon_id'
  const ownerId = identity.userId ?? identity.anonymousId

  if (!ownerId) {
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

  const existingUpload = await env.DB.prepare(
    `SELECT id
     FROM uploads
     WHERE id = ?
       AND ${ownerField} = ?
       AND deleted_at IS NULL
     LIMIT 1`,
  )
    .bind(uploadId, ownerId)
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
         AND ${ownerField} = ?
         AND deleted_at IS NULL`,
    )
      .bind(nowIso, nowIso, uploadId, ownerId)
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

  const formData = await request.formData()
  const fileEntry = formData.get('file')

  if (!(fileEntry instanceof File)) {
    return respondJson(
      {
        error: "Missing file field. Send a multipart field named 'file'.",
      },
      400,
    )
  }

  if (fileEntry.size <= 0) {
    return respondJson(
      {
        error: 'Uploaded file is empty.',
      },
      400,
    )
  }

  if (fileEntry.size > MAX_UPLOAD_SIZE_BYTES) {
    return respondJson(
      {
        error: 'File too large. Maximum upload size is 15 MB.',
      },
      413,
    )
  }

  const mimeType = fileEntry.type.toLowerCase()
  const expectedExtension = MIME_TO_EXTENSION[mimeType]

  if (!expectedExtension) {
    return respondJson(
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
      return respondJson(
        {
          error: 'File extension does not match MIME type.',
        },
        400,
      )
    }
  }

  const fileBuffer = await fileEntry.arrayBuffer()
  const fileBytes = new Uint8Array(fileBuffer)

  if (!hasValidImageSignature(fileBytes, mimeType)) {
    return respondJson(
      {
        error: 'File content signature is not a valid image.',
      },
      400,
    )
  }

  const identity = await resolveRequestIdentity(request, env, {
    ensureAnonymousId: true,
    migrateAnonymousToUser: true,
  })

  const respondWithIdentity = (
    body: Record<string, unknown>,
    status: number,
  ): Response => {
    return withSetCookieHeader(
      respondJson(body, status),
      identity.setCookieHeader,
    )
  }

  const ownerUserId = identity.userId
  const ownerAnonymousId = ownerUserId ? null : identity.anonymousId

  if (!ownerUserId) {
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
          error: `Anonymous library limit reached (${MAX_ANONYMOUS_UPLOADS} images). Sign in to store more.`,
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
  async fetch(request: Request, env: Env) {
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
    }

    if (url.pathname.startsWith('/i/')) {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return methodNotAllowed('GET, HEAD')
      }
      return handlePublicImageRequest(request, env)
    }

    return handler.fetch(request)
  },
} satisfies WorkerHandler
