import handler from '@tanstack/solid-start/server-entry'
import { auth } from '../lib/auth'

const MAX_UPLOAD_SIZE_BYTES = 15 * 1024 * 1024
const ANONYMOUS_UPLOAD_EXPIRY_DAYS = 30
const SESSION_LOOKUP_TIMEOUT_MS = 1_500
const ULID_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

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
      bind: (...values: unknown[]) => {
        run: () => Promise<unknown>
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

const respondJson = (body: Record<string, unknown>, status = 200): Response => {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
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

const hasSignature = (bytes: Uint8Array, signature: number[]): boolean => {
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

  const id = createUlid()
  const r2Key = `${id}/original.${expectedExtension}`
  const directUrl = toDirectUrl(request, r2Key)
  const nowIso = new Date().toISOString()
  const ownerUserId = await getAuthenticatedUserId(request)
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
    return respondJson(
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
        expires_at,
        r2_key,
        public_url,
        mime_type,
        size_bytes,
        optimization_status,
        sha256,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`,
    )
      .bind(
        id,
        ownerUserId,
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
    return respondJson(
      {
        error: 'Failed to persist upload metadata.',
      },
      500,
    )
  }

  return respondJson(createUploadPayload(id, directUrl), 201)
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
