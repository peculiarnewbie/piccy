import { createFileRoute } from '@tanstack/solid-router'
import {
  For,
  Show,
  createEffect,
  createSignal,
  on,
  onCleanup,
  onMount,
} from 'solid-js'
import { authClient } from '../lib/auth-client'

export const Route = createFileRoute('/library')({ component: LibraryRoute })

function LibraryRoute() {
  return <LibraryWorkspace />
}

/* ── Types ── */

type UploadPayload = {
  id: string
  directUrl: string
  markdown: string
  bbcode: string
}

type CopyFormat = 'direct' | 'markdown' | 'bbcode'
type CopySource = 'uploader' | 'library'

type LibraryItem = UploadPayload & {
  thumbUrl: string
  mimeType: string
  sizeBytes: number
  width: number | null
  height: number | null
  copyCount: number
  createdAt: string
  isSeeded?: boolean
}

type LibraryResponse = {
  items: Array<LibraryItem>
  nextCursor: string | null
  mode: 'user' | 'anonymous'
}

type ToastTone = 'success' | 'error' | 'info'

type ToastEntry = {
  id: string
  tone: ToastTone
  message: string
}

type UploadEntitlements = {
  isAuthenticated: boolean
  isPaid: boolean
  multiFileUploadEnabled: boolean
  libraryLimit: number
  libraryUsage: number
}

type CopyTrackingInput = {
  uploadId: string
  format: CopyFormat
  source: CopySource
}

/* ── Constants ── */

const MAX_SIZE_BYTES = 15 * 1024 * 1024
const UPLOAD_REQUEST_TIMEOUT_MS = 90_000
const UPLOAD_MAX_ATTEMPTS = 2

const LIBRARY_SKELETON_HEIGHTS = [
  74, 122, 98, 146, 84, 136, 112, 158, 92, 128, 104, 150,
]

const LIBRARY_ZOOM_DEFAULT = 0

/* ── Helpers ── */

class UploadRequestError extends Error {
  readonly retryable: boolean

  constructor(message: string, retryable: boolean) {
    super(message)
    this.name = 'UploadRequestError'
    this.retryable = retryable
  }
}

const parseUploadError = (status: number, responseText: string): string => {
  if (!responseText) {
    return `Upload failed (${status}).`
  }

  try {
    const parsed = JSON.parse(responseText) as { error?: string }
    if (parsed.error) {
      return parsed.error
    }
  } catch {
    return `Upload failed (${status}).`
  }

  return `Upload failed (${status}).`
}

const isRetryableHttpStatus = (status: number): boolean => {
  return status === 408 || status === 429 || status >= 500
}

const uploadWithProgress = (
  file: File,
  onProgress: (value: number) => void,
  batchSize: number,
): Promise<UploadPayload> => {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest()
    const formData = new FormData()

    formData.append('file', file)
    formData.append('batchSize', String(batchSize))
    request.open('POST', '/api/uploads')
    request.timeout = UPLOAD_REQUEST_TIMEOUT_MS

    request.upload.onprogress = (event) => {
      if (!event.lengthComputable) {
        return
      }

      const nextProgress = Math.min(
        100,
        Math.round((event.loaded / event.total) * 100),
      )
      onProgress(nextProgress)
    }

    request.onerror = () => {
      reject(new UploadRequestError('Network error while uploading.', true))
    }

    request.onabort = () => {
      reject(
        new UploadRequestError(
          'Upload was cancelled. Please try again.',
          false,
        ),
      )
    }

    request.ontimeout = () => {
      reject(
        new UploadRequestError(
          'Upload timed out while waiting for server response.',
          true,
        ),
      )
    }

    request.onload = () => {
      if (request.status < 200 || request.status >= 300) {
        reject(
          new UploadRequestError(
            parseUploadError(request.status, request.responseText),
            isRetryableHttpStatus(request.status),
          ),
        )
        return
      }

      try {
        const payload = JSON.parse(request.responseText) as UploadPayload
        resolve(payload)
      } catch {
        reject(
          new UploadRequestError(
            'Upload succeeded but response parsing failed.',
            false,
          ),
        )
      }
    }

    request.send(formData)
  })
}

const sleep = async (milliseconds: number): Promise<void> => {
  await new Promise((resolve) => {
    window.setTimeout(resolve, milliseconds)
  })
}

const uploadWithRetry = async (
  file: File,
  onProgress: (value: number) => void,
  batchSize: number,
): Promise<UploadPayload> => {
  let attempt = 0

  while (attempt < UPLOAD_MAX_ATTEMPTS) {
    try {
      return await uploadWithProgress(file, onProgress, batchSize)
    } catch (error) {
      attempt += 1

      const isRetryable =
        error instanceof UploadRequestError ? error.retryable : false

      if (!isRetryable || attempt >= UPLOAD_MAX_ATTEMPTS) {
        throw error
      }

      onProgress(0)
      await sleep(450 * attempt)
    }
  }

  throw new UploadRequestError('Upload failed unexpectedly.', false)
}

const copyToClipboard = async (value: string): Promise<void> => {
  if (
    'clipboard' in navigator &&
    typeof navigator.clipboard.writeText === 'function'
  ) {
    await navigator.clipboard.writeText(value)
    return
  }

  const textArea = document.createElement('textarea')
  textArea.value = value
  textArea.style.position = 'fixed'
  textArea.style.left = '-9999px'
  document.body.append(textArea)
  textArea.select()
  document.execCommand('copy')
  textArea.remove()
}

const trackCopyEvent = async (
  uploadId: string,
  format: CopyFormat,
  source: CopySource,
): Promise<void> => {
  try {
    const response = await fetch(
      `/api/uploads/${encodeURIComponent(uploadId)}/copy`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          format,
          source,
        }),
      },
    )

    if (!response.ok) {
      throw new Error(`Copy tracking failed (${response.status})`)
    }
  } catch (error) {
    console.warn('Copy tracking request failed', error)
  }
}

const parseJsonErrorMessage = async (
  response: Response,
  fallback: string,
): Promise<string> => {
  try {
    const payload = (await response.json()) as { error?: string }
    if (payload.error) {
      return payload.error
    }
  } catch {
    return fallback
  }

  return fallback
}

const fetchLibraryPage = async (
  cursor: string | null,
): Promise<LibraryResponse> => {
  const url = new URL('/api/me/uploads', window.location.origin)
  if (cursor) {
    url.searchParams.set('cursor', cursor)
  }

  const response = await fetch(url.toString())

  if (!response.ok) {
    throw new Error(
      await parseJsonErrorMessage(
        response,
        `Failed to load library (${response.status}).`,
      ),
    )
  }

  return (await response.json()) as LibraryResponse
}

const fetchUploadEntitlements = async (): Promise<UploadEntitlements> => {
  const response = await fetch('/api/me/entitlements')

  if (!response.ok) {
    throw new Error(
      await parseJsonErrorMessage(
        response,
        `Failed to load upload entitlements (${response.status}).`,
      ),
    )
  }

  return (await response.json()) as UploadEntitlements
}

const deleteLibraryUpload = async (uploadId: string): Promise<void> => {
  const response = await fetch(
    `/api/me/uploads/${encodeURIComponent(uploadId)}`,
    {
      method: 'DELETE',
    },
  )

  if (response.status === 204) {
    return
  }

  throw new Error(
    await parseJsonErrorMessage(
      response,
      `Delete failed (${response.status}).`,
    ),
  )
}

const getFormatLabel = (format: CopyFormat): string => {
  if (format === 'direct') {
    return 'Direct URL copied'
  }

  if (format === 'markdown') {
    return 'Markdown copied'
  }

  return 'BBCode copied'
}

const getFormatValue = (item: UploadPayload, format: CopyFormat): string => {
  if (format === 'direct') {
    return item.directUrl
  }

  if (format === 'markdown') {
    return item.markdown
  }

  return item.bbcode
}

const isTextInputTarget = (target: EventTarget | null): boolean => {
  if (!(target instanceof HTMLElement)) {
    return false
  }

  const tagName = target.tagName.toLowerCase()
  if (tagName === 'input' || tagName === 'textarea' || tagName === 'select') {
    return true
  }

  return target.isContentEditable
}

const clampNumber = (value: number, min: number, max: number): number => {
  return Math.min(max, Math.max(min, value))
}

const getBaseLibraryColumnCount = (width: number): number => {
  if (width >= 1280) {
    return 4
  }

  if (width >= 768) {
    return 3
  }

  return 2
}

const getMaxLibraryColumnCount = (width: number): number => {
  if (width >= 1280) {
    return 7
  }

  if (width >= 768) {
    return 5
  }

  return 4
}

const getMinLibraryColumnCount = (width: number): number => {
  if (width >= 1280) {
    return 3
  }

  if (width >= 768) {
    return 2
  }

  return 1
}

const getLibraryZoomBounds = (
  width: number,
): {
  minOffset: number
  maxOffset: number
} => {
  const baseColumnCount = getBaseLibraryColumnCount(width)
  const maxColumnCount = getMaxLibraryColumnCount(width)
  const minColumnCount = getMinLibraryColumnCount(width)

  return {
    minOffset: baseColumnCount - maxColumnCount,
    maxOffset: baseColumnCount - minColumnCount,
  }
}

/* ── Component ── */

function LibraryWorkspace() {
  const session = authClient.useSession()

  const [dragging, setDragging] = createSignal(false)
  const [isUploading, setIsUploading] = createSignal(false)
  const [progress, setProgress] = createSignal(0)
  const [uploadQueueIndex, setUploadQueueIndex] = createSignal(0)
  const [uploadQueueTotal, setUploadQueueTotal] = createSignal(0)
  const [uploadError, setUploadError] = createSignal('')
  const [uploadResult, setUploadResult] = createSignal<UploadPayload | null>(
    null,
  )
  const [previewName, setPreviewName] = createSignal('')
  const [uploadEntitlements, setUploadEntitlements] =
    createSignal<UploadEntitlements | null>(null)

  const [uploadPanelOpen, setUploadPanelOpen] = createSignal(false)

  const [libraryItems, setLibraryItems] = createSignal<Array<LibraryItem>>([])
  const [libraryNextCursor, setLibraryNextCursor] = createSignal<string | null>(
    null,
  )
  const [libraryError, setLibraryError] = createSignal('')
  const [libraryLoadingInitial, setLibraryLoadingInitial] = createSignal(true)
  const [libraryLoadingMore, setLibraryLoadingMore] = createSignal(false)
  const [libraryZoomOffset, setLibraryZoomOffset] =
    createSignal(LIBRARY_ZOOM_DEFAULT)
  const [viewportWidth, setViewportWidth] = createSignal(1280)

  const [cardFormats, setCardFormats] = createSignal<
    Partial<Record<string, CopyFormat>>
  >({})
  const [copiedCardId, setCopiedCardId] = createSignal<string | null>(null)
  const [deletingById, setDeletingById] = createSignal<
    Partial<Record<string, true>>
  >({})
  const [focusedIndex, setFocusedIndex] = createSignal(-1)
  const [highlightedUploadId, setHighlightedUploadId] = createSignal<
    string | null
  >(null)

  const [toasts, setToasts] = createSignal<Array<ToastEntry>>([])

  const cardRefs = new Map<string, HTMLDivElement>()

  let fileInputRef: HTMLInputElement | undefined
  let libraryScrollRef: HTMLDivElement | undefined
  let copiedCardTimer: number | undefined
  let highlightedUploadTimer: number | undefined

  const pushToast = (tone: ToastTone, message: string, ttlMs = 2200) => {
    const id =
      typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`

    setToasts((current) => [...current, { id, tone, message }])

    window.setTimeout(() => {
      setToasts((current) => current.filter((toast) => toast.id !== id))
    }, ttlMs)
  }

  const markCopiedCard = (uploadId: string) => {
    setCopiedCardId(uploadId)

    if (copiedCardTimer !== undefined) {
      window.clearTimeout(copiedCardTimer)
    }

    copiedCardTimer = window.setTimeout(() => {
      setCopiedCardId(null)
      copiedCardTimer = undefined
    }, 720)
  }

  const markRecentlyUploadedCard = (uploadId: string) => {
    setHighlightedUploadId(uploadId)

    if (highlightedUploadTimer !== undefined) {
      window.clearTimeout(highlightedUploadTimer)
    }

    highlightedUploadTimer = window.setTimeout(() => {
      setHighlightedUploadId(null)
      highlightedUploadTimer = undefined
    }, 2800)
  }

  const getCardFormat = (uploadId: string): CopyFormat => {
    return cardFormats()[uploadId] ?? 'direct'
  }

  const getLibraryColumnCount = (): number => {
    const width = viewportWidth()
    const baseColumnCount = getBaseLibraryColumnCount(width)
    const zoomBounds = getLibraryZoomBounds(width)
    const zoomOffset = clampNumber(
      libraryZoomOffset(),
      zoomBounds.minOffset,
      zoomBounds.maxOffset,
    )

    return baseColumnCount - zoomOffset
  }

  const setLibraryZoom = (nextZoomOffset: number): void => {
    const zoomBounds = getLibraryZoomBounds(viewportWidth())

    setLibraryZoomOffset(
      clampNumber(nextZoomOffset, zoomBounds.minOffset, zoomBounds.maxOffset),
    )
  }

  const canZoomOut = (): boolean => {
    const zoomBounds = getLibraryZoomBounds(viewportWidth())
    return libraryZoomOffset() > zoomBounds.minOffset
  }

  const canZoomIn = (): boolean => {
    const zoomBounds = getLibraryZoomBounds(viewportWidth())
    return libraryZoomOffset() < zoomBounds.maxOffset
  }

  const setCardFormat = (uploadId: string, format: CopyFormat) => {
    setCardFormats((current) => ({
      ...current,
      [uploadId]: format,
    }))
  }

  const copyValue = async (
    value: string,
    label: string,
    tracking?: CopyTrackingInput,
  ): Promise<void> => {
    try {
      await copyToClipboard(value)
      pushToast('success', label)

      if (tracking && session().data?.user) {
        void trackCopyEvent(tracking.uploadId, tracking.format, tracking.source)
      }
    } catch {
      pushToast('error', 'Copy failed. Please copy manually.')
    }
  }

  const copyLibraryItem = async (
    item: LibraryItem,
    format: CopyFormat,
  ): Promise<void> => {
    setCardFormat(item.id, format)
    const tracking = item.isSeeded
      ? undefined
      : {
          uploadId: item.id,
          format,
          source: 'library' as const,
        }

    await copyValue(
      getFormatValue(item, format),
      getFormatLabel(format),
      tracking,
    )
    markCopiedCard(item.id)
  }

  const loadLibraryPage = async (
    cursor: string | null,
    append: boolean,
  ): Promise<void> => {
    if (append) {
      if (libraryLoadingMore()) {
        return
      }
      setLibraryLoadingMore(true)
    } else {
      if (libraryLoadingInitial()) {
        setLibraryError('')
      }
      setLibraryLoadingInitial(true)
      setLibraryError('')
    }

    try {
      const payload = await fetchLibraryPage(cursor)

      setLibraryItems((current) =>
        append ? [...current, ...payload.items] : payload.items,
      )
      setLibraryNextCursor(payload.nextCursor)

      setCardFormats((current) => {
        const next = { ...current }
        for (const item of payload.items) {
          if (!next[item.id]) {
            next[item.id] = 'direct'
          }
        }
        return next
      })
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : 'Failed to load uploads unexpectedly.'

      if (append) {
        pushToast('error', message)
      } else {
        setLibraryError(message)
      }
    } finally {
      setLibraryLoadingInitial(false)
      setLibraryLoadingMore(false)
    }
  }

  const reloadLibrary = async (): Promise<void> => {
    setFocusedIndex(-1)
    await loadLibraryPage(null, false)
  }

  const loadNextLibraryPage = async (): Promise<void> => {
    const nextCursor = libraryNextCursor()
    if (!nextCursor) {
      return
    }

    await loadLibraryPage(nextCursor, true)
  }

  const maybeLoadNextPageFromScroll = () => {
    if (!libraryScrollRef || !libraryNextCursor() || libraryLoadingMore()) {
      return
    }

    const threshold = 240
    const distanceFromBottom =
      libraryScrollRef.scrollHeight -
      libraryScrollRef.scrollTop -
      libraryScrollRef.clientHeight

    if (distanceFromBottom <= threshold) {
      void loadNextLibraryPage()
    }
  }

  const loadUploadEntitlements = async (): Promise<void> => {
    try {
      const entitlements = await fetchUploadEntitlements()
      setUploadEntitlements(entitlements)
    } catch {
      setUploadEntitlements(null)
    }
  }

  const getUploadValidationError = (file: File): string | null => {
    if (!file.type.startsWith('image/')) {
      return 'Please choose an image file.'
    }

    if (file.size <= 0) {
      return 'Uploaded file is empty.'
    }

    if (file.size > MAX_SIZE_BYTES) {
      return 'File too large. Maximum upload size is 15 MB.'
    }

    return null
  }

  const canUseMultiFileUpload = (): boolean => {
    const entitlements = uploadEntitlements()
    if (entitlements) {
      return entitlements.multiFileUploadEnabled
    }

    return Boolean(session().data?.user)
  }

  const startUploadBatch = async (files: Array<File>) => {
    if (isUploading()) {
      pushToast('info', 'Upload in progress. Please wait for it to finish.')
      return
    }

    if (files.length === 0) {
      return
    }

    setUploadError('')
    setUploadResult(null)

    if (files.length > 1 && !canUseMultiFileUpload()) {
      const message = session().data?.user
        ? 'Multi-file upload is available on paid accounts only.'
        : 'Multi-file upload is available on paid accounts. Sign in to continue.'

      setUploadError(message)
      pushToast('info', message)
      return
    }

    for (const file of files) {
      const validationError = getUploadValidationError(file)
      if (!validationError) {
        continue
      }

      const label = file.name
        ? `${file.name}: ${validationError}`
        : validationError
      setUploadError(label)
      return
    }

    // Auto-open the upload panel so the user sees progress
    setUploadPanelOpen(true)

    setPreviewName('')
    setProgress(0)
    setUploadQueueIndex(0)
    setUploadQueueTotal(files.length)
    setIsUploading(true)

    const uploadedPayloads: Array<UploadPayload> = []
    const uploadFailures: Array<string> = []

    try {
      for (let index = 0; index < files.length; index += 1) {
        const file = files[index]
        setUploadQueueIndex(index + 1)
        setPreviewName(file.name || 'clipboard-image')
        setProgress(0)

        try {
          const payload = await uploadWithRetry(file, setProgress, files.length)
          uploadedPayloads.push(payload)
        } catch (error) {
          const message =
            error instanceof Error
              ? error.message
              : 'Upload failed unexpectedly.'
          uploadFailures.push(
            file.name
              ? `${file.name}: ${message}`
              : `Image ${index + 1}: ${message}`,
          )
        }
      }

      if (uploadedPayloads.length > 0) {
        const latestUpload = uploadedPayloads[uploadedPayloads.length - 1]
        setUploadResult(latestUpload)

        const autoCopyUpload = uploadedPayloads[0]
        const copyLabel =
          uploadedPayloads.length === 1 && files.length === 1
            ? 'Direct URL copied'
            : 'First uploaded URL copied'

        await copyValue(autoCopyUpload.directUrl, copyLabel, {
          uploadId: autoCopyUpload.id,
          format: 'direct',
          source: 'uploader',
        })

        if (uploadedPayloads.length > 1) {
          pushToast(
            'success',
            `Uploaded ${uploadedPayloads.length}/${files.length} images.`,
          )
        }

        await reloadLibrary()
        void loadUploadEntitlements()

        // Highlight the most recent upload in the grid
        markRecentlyUploadedCard(latestUpload.id)
      }

      if (uploadFailures.length > 0) {
        const message =
          uploadFailures.length === 1
            ? uploadFailures[0]
            : `${uploadFailures.length} uploads failed.`

        setUploadError(message)
        pushToast('error', message)
      }

      if (uploadedPayloads.length === 0 && uploadFailures.length === 0) {
        setUploadError('No uploadable images were found.')
      }
    } finally {
      setIsUploading(false)
      setProgress(100)
      setUploadQueueIndex(0)
      setUploadQueueTotal(0)
    }
  }

  const onInputFileSelect = (event: Event) => {
    const currentTarget = event.currentTarget as HTMLInputElement
    const selectedFiles = currentTarget.files
      ? Array.from(currentTarget.files)
      : []
    currentTarget.value = ''

    if (selectedFiles.length === 0) {
      return
    }

    void startUploadBatch(selectedFiles)
  }

  const onDrop = (event: DragEvent) => {
    event.preventDefault()
    setDragging(false)

    const selectedFiles = Array.from(event.dataTransfer?.files ?? []).filter(
      (file) => file.type.startsWith('image/'),
    )

    if (selectedFiles.length === 0) {
      return
    }

    void startUploadBatch(selectedFiles)
  }

  const focusCardByIndex = (nextIndex: number) => {
    const items = libraryItems()
    if (items.length === 0) {
      setFocusedIndex(-1)
      return
    }

    const clampedIndex = Math.max(0, Math.min(nextIndex, items.length - 1))
    setFocusedIndex(clampedIndex)

    const item = items[clampedIndex]
    const targetElement = cardRefs.get(item.id)
    if (!targetElement) {
      return
    }

    targetElement.focus({ preventScroll: true })
    targetElement.scrollIntoView({ block: 'nearest', inline: 'nearest' })
  }

  const copyFocusedCard = (format: CopyFormat) => {
    const index = focusedIndex()
    const items = libraryItems()
    if (index < 0 || index >= items.length) {
      return
    }

    const item = items[index]
    void copyLibraryItem(item, format)
  }

  const deleteUploadById = async (uploadId: string): Promise<void> => {
    if (deletingById()[uploadId]) {
      return
    }

    const snapshot = libraryItems()
    const index = snapshot.findIndex((item) => item.id === uploadId)
    if (index === -1) {
      return
    }

    const item = snapshot[index]
    const confirmed = window.confirm(
      'Delete this upload? It can be recovered only until cleanup runs.',
    )
    if (!confirmed) {
      return
    }

    setDeletingById((current) => ({
      ...current,
      [uploadId]: true,
    }))

    setLibraryItems((current) =>
      current.filter((entry) => entry.id !== uploadId),
    )
    cardRefs.delete(uploadId)

    if (snapshot.length <= 1) {
      setFocusedIndex(-1)
    } else if (focusedIndex() >= snapshot.length - 1) {
      setFocusedIndex(snapshot.length - 2)
    }

    try {
      await deleteLibraryUpload(uploadId)
      pushToast('success', 'Upload deleted')
      void loadUploadEntitlements()
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Failed to delete upload.'

      setLibraryItems((current) => {
        if (current.some((entry) => entry.id === uploadId)) {
          return current
        }

        const restored = [...current]
        restored.splice(Math.min(index, restored.length), 0, item)
        return restored
      })
      pushToast('error', message)
    } finally {
      setDeletingById((current) => {
        const next = { ...current }
        delete next[uploadId]
        return next
      })
    }
  }

  createEffect(
    on(
      () => (session().isPending ? undefined : session().data?.user?.id),
      () => {
        void loadUploadEntitlements()
        void reloadLibrary()
      },
      { defer: true },
    ),
  )

  createEffect(() => {
    const zoomBounds = getLibraryZoomBounds(viewportWidth())

    setLibraryZoomOffset((current) =>
      clampNumber(current, zoomBounds.minOffset, zoomBounds.maxOffset),
    )
  })

  onMount(() => {
    void loadUploadEntitlements()
    void reloadLibrary()

    const handleWindowResize = () => {
      setViewportWidth(window.innerWidth)
    }

    handleWindowResize()

    const handlePaste = (event: ClipboardEvent) => {
      const items = event.clipboardData?.items
      if (!items) {
        return
      }

      const pastedFiles: Array<File> = []

      for (const item of items) {
        if (!item.type.startsWith('image/')) {
          continue
        }

        const pastedFile = item.getAsFile()
        if (!pastedFile) {
          continue
        }

        pastedFiles.push(pastedFile)
      }

      if (pastedFiles.length === 0) {
        return
      }

      event.preventDefault()
      void startUploadBatch(pastedFiles)
    }

    const handleWindowKeyDown = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey || event.shiftKey) {
        return
      }

      if (isTextInputTarget(event.target)) {
        return
      }

      if (libraryItems().length === 0) {
        return
      }

      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
        event.preventDefault()
        focusCardByIndex(focusedIndex() < 0 ? 0 : focusedIndex() + 1)
        return
      }

      if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
        event.preventDefault()
        focusCardByIndex(focusedIndex() <= 0 ? 0 : focusedIndex() - 1)
        return
      }

      if (event.key === 'Enter' || event.key === 'c') {
        event.preventDefault()
        copyFocusedCard('direct')
        return
      }

      if (event.key === 'm') {
        event.preventDefault()
        copyFocusedCard('markdown')
        return
      }

      if (event.key === 'b') {
        event.preventDefault()
        copyFocusedCard('bbcode')
        return
      }

      if (event.key === 'Delete' || event.key === 'd') {
        event.preventDefault()
        const index = focusedIndex()
        const items = libraryItems()
        if (index >= 0 && index < items.length) {
          void deleteUploadById(items[index].id)
        }
        return
      }

      if (event.key === 'Escape') {
        setFocusedIndex(-1)
      }
    }

    window.addEventListener('resize', handleWindowResize)
    window.addEventListener('paste', handlePaste)
    window.addEventListener('keydown', handleWindowKeyDown)

    onCleanup(() => {
      window.removeEventListener('resize', handleWindowResize)
      window.removeEventListener('paste', handlePaste)
      window.removeEventListener('keydown', handleWindowKeyDown)
    })
  })

  onCleanup(() => {
    if (copiedCardTimer !== undefined) {
      window.clearTimeout(copiedCardTimer)
    }

    if (highlightedUploadTimer !== undefined) {
      window.clearTimeout(highlightedUploadTimer)
    }
  })

  /* ── Render ── */

  return (
    <div class="min-h-screen pt-[54px] animate-route-enter">
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept="image/png,image/jpeg,image/gif,image/webp"
        class="hidden"
        onChange={onInputFileSelect}
      />

      <div class="flex h-[calc(100vh-54px)]">
        {/* ── Library (primary content) ── */}
        <div class="flex-1 min-w-0 flex flex-col">
          {/* Library header */}
          <div class="flex items-end justify-between gap-4 flex-wrap px-5 md:px-7 pt-5 pb-4 border-b-2 border-border">
            <div>
              <h1 class="text-[clamp(22px,3vw,30px)] font-[800] tracking-[-0.8px] leading-[1.15]">
                Library
              </h1>
              <p class="font-mono text-[12px] text-text-dim mt-1">
                Click an image to copy. Use URL, MD, or BB on each card.
              </p>
            </div>

            <div class="flex items-center gap-2.5 flex-wrap">
              <Show
                when={uploadEntitlements()}
                fallback={
                  <div class="px-3 py-1.5 rounded-full border border-border-heavy bg-surface-2 font-mono text-[11px] uppercase tracking-[1px] text-text-dim">
                    ...
                  </div>
                }
              >
                {(ent) => {
                  const used = () => ent().libraryUsage
                  const limit = () => ent().libraryLimit
                  const pct = () =>
                    limit() > 0
                      ? Math.min(100, Math.round((used() / limit()) * 100))
                      : 0
                  const isNearLimit = () => pct() >= 85
                  const isGuest = () => !session().data?.user

                  return (
                    <>
                      <div
                        class={`flex items-center gap-2.5 px-3 py-1.5 rounded-full border bg-surface-2 ${
                          isNearLimit()
                            ? 'border-accent/40'
                            : 'border-border-heavy'
                        }`}
                      >
                        <div class="w-20 md:w-24 h-[6px] rounded-full bg-bg overflow-hidden">
                          <div
                            class={`h-full rounded-full transition-all duration-500 ${
                              isNearLimit() ? 'bg-accent' : 'bg-mint'
                            }`}
                            style={{ width: `${Math.max(pct(), 2)}%` }}
                          />
                        </div>
                        <span
                          class={`font-mono text-[10px] tracking-[0.5px] tabular-nums whitespace-nowrap ${
                            isNearLimit() ? 'text-accent' : 'text-text-dim'
                          }`}
                        >
                          {used().toLocaleString()}
                          <span class="text-text-dim/50">/</span>
                          {limit().toLocaleString()}
                        </span>
                      </div>

                      <Show when={isGuest()}>
                        <a
                          href="/better-auth"
                          class="group flex items-center gap-2 px-3.5 py-1.5 rounded-full border border-accent/50 bg-accent/8 hover:bg-accent/15 hover:border-accent transition-all"
                        >
                          <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            class="w-3.5 h-3.5 stroke-accent"
                            stroke-width="2.5"
                          >
                            <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
                            <polyline points="10 17 15 12 10 7" />
                            <line x1="15" y1="12" x2="3" y2="12" />
                          </svg>
                          <span class="font-mono text-[11px] font-medium tracking-[0.5px] text-accent">
                            Sign in for more
                          </span>
                        </a>
                      </Show>
                    </>
                  )
                }}
              </Show>
              <div class="flex items-center gap-2 rounded-full border border-border-heavy bg-surface-2 px-3 py-1.5">
                <span class="font-mono text-[10px] uppercase tracking-[1px] text-text-dim">
                  Zoom
                </span>
                <button
                  type="button"
                  class={`h-6 w-6 rounded-full border bg-surface transition-colors ${
                    canZoomOut()
                      ? 'border-border-heavy text-text-dim hover:text-text hover:border-text-dim'
                      : 'border-border text-text-dim/45 cursor-not-allowed'
                  }`}
                  onClick={() => setLibraryZoom(libraryZoomOffset() - 1)}
                  disabled={!canZoomOut()}
                  aria-label="Zoom out library grid"
                >
                  -
                </button>
                <input
                  type="range"
                  min={getLibraryZoomBounds(viewportWidth()).minOffset}
                  max={getLibraryZoomBounds(viewportWidth()).maxOffset}
                  step="1"
                  value={libraryZoomOffset()}
                  class="w-20 md:w-24 accent-accent"
                  onInput={(event) => {
                    const nextValue = Number(event.currentTarget.value)
                    if (Number.isNaN(nextValue)) {
                      return
                    }

                    setLibraryZoom(nextValue)
                  }}
                  aria-label="Adjust library zoom"
                />
                <button
                  type="button"
                  class={`h-6 w-6 rounded-full border bg-surface transition-colors ${
                    canZoomIn()
                      ? 'border-border-heavy text-text-dim hover:text-text hover:border-text-dim'
                      : 'border-border text-text-dim/45 cursor-not-allowed'
                  }`}
                  onClick={() => setLibraryZoom(libraryZoomOffset() + 1)}
                  disabled={!canZoomIn()}
                  aria-label="Zoom in library grid"
                >
                  +
                </button>
                <span class="min-w-[52px] text-right font-mono text-[10px] uppercase tracking-[1px] text-text-dim">
                  {getLibraryColumnCount()} cols
                </span>
              </div>
              <button
                type="button"
                class="btn btn-accent"
                onClick={() => setUploadPanelOpen((open) => !open)}
              >
                <Show
                  when={uploadPanelOpen()}
                  fallback={
                    <>
                      <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        class="w-4 h-4 stroke-current"
                        stroke-width="2.5"
                      >
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                        <polyline points="17 8 12 3 7 8" />
                        <line x1="12" y1="3" x2="12" y2="15" />
                      </svg>
                      Upload
                    </>
                  }
                >
                  <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    class="w-4 h-4 stroke-current"
                    stroke-width="2.5"
                  >
                    <line x1="18" y1="6" x2="6" y2="18" />
                    <line x1="6" y1="6" x2="18" y2="18" />
                  </svg>
                  Close
                </Show>
              </button>
            </div>
          </div>

          {/* Library grid */}
          <div
            ref={libraryScrollRef}
            class="flex-1 min-h-0 p-3 md:p-4 overflow-y-auto"
            onScroll={maybeLoadNextPageFromScroll}
          >
            <Show
              when={!libraryLoadingInitial()}
              fallback={
                <div
                  class="gap-2 [column-fill:_balance]"
                  style={{ 'column-count': getLibraryColumnCount() }}
                >
                  <For each={LIBRARY_SKELETON_HEIGHTS}>
                    {(height) => (
                      <div
                        class="mb-2 break-inside-avoid rounded-[10px] border-2 border-border bg-surface-2/80 animate-pulse"
                        style={{ height: `${height}px` }}
                      />
                    )}
                  </For>
                </div>
              }
            >
              <Show
                when={!libraryError()}
                fallback={
                  <div class="h-full flex items-center justify-center text-center px-6">
                    <div>
                      <p class="text-sm font-semibold text-accent mb-2">
                        {libraryError()}
                      </p>
                      <button
                        type="button"
                        class="btn btn-outline text-[12px] py-1.5 px-3"
                        onClick={() => {
                          void reloadLibrary()
                        }}
                      >
                        Retry
                      </button>
                    </div>
                  </div>
                }
              >
                <Show
                  when={libraryItems().length > 0}
                  fallback={
                    <div class="h-full flex items-center justify-center text-center px-6">
                      <div>
                        <p class="text-base font-[800] mb-1">No uploads yet</p>
                        <p class="font-mono text-[12px] text-text-dim mb-4">
                          Paste, drop, or click Upload to add your first image.
                        </p>
                        <button
                          type="button"
                          class="btn btn-accent"
                          onClick={() => setUploadPanelOpen(true)}
                        >
                          <svg
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            class="w-4 h-4 stroke-current"
                            stroke-width="2.5"
                          >
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                            <polyline points="17 8 12 3 7 8" />
                            <line x1="12" y1="3" x2="12" y2="15" />
                          </svg>
                          Upload image
                        </button>
                      </div>
                    </div>
                  }
                >
                  <div
                    class="gap-2 [column-fill:_balance]"
                    style={{ 'column-count': getLibraryColumnCount() }}
                  >
                    <For each={libraryItems()}>
                      {(item, index) => {
                        const isFocused = () => focusedIndex() === index()
                        const isCopied = () => copiedCardId() === item.id
                        const isRecentlyUploaded = () =>
                          highlightedUploadId() === item.id
                        const isDeleting = () =>
                          Boolean(deletingById()[item.id])

                        return (
                          <div
                            ref={(element) => {
                              cardRefs.set(item.id, element)
                            }}
                            role="button"
                            tabindex="0"
                            class={`group relative mb-2 break-inside-avoid overflow-hidden rounded-[10px] border-2 transition-all outline-none ${
                              isCopied()
                                ? 'border-mint ring-2 ring-mint/40'
                                : isRecentlyUploaded()
                                  ? 'border-secondary ring-2 ring-secondary/45 uploaded-flash'
                                  : isFocused()
                                    ? 'border-accent ring-2 ring-accent/35'
                                    : 'border-border hover:border-border-heavy'
                            } ${isDeleting() ? 'opacity-60' : ''}`}
                            onFocus={() => {
                              setFocusedIndex(index())
                            }}
                            onClick={() => {
                              if (isDeleting()) {
                                return
                              }

                              void copyLibraryItem(item, getCardFormat(item.id))
                            }}
                            onKeyDown={(event) => {
                              if (event.key === 'Enter' || event.key === ' ') {
                                event.preventDefault()
                                if (isDeleting()) {
                                  return
                                }

                                void copyLibraryItem(
                                  item,
                                  getCardFormat(item.id),
                                )
                              }
                            }}
                          >
                            <img
                              src={item.thumbUrl}
                              alt=""
                              loading="lazy"
                              decoding="async"
                              class="block w-full h-auto bg-surface-2"
                            />

                            <div class="pointer-events-none absolute inset-0 bg-gradient-to-t from-bg/65 to-transparent opacity-65 group-hover:opacity-90 transition-opacity" />

                            <Show when={item.copyCount > 0}>
                              <div class="absolute top-1.5 left-1.5 px-2 py-0.5 rounded-full border border-border-heavy bg-surface/95 font-mono text-[10px] text-text-dim">
                                {item.copyCount} copies
                              </div>
                            </Show>

                            <div class="absolute top-1.5 right-1.5 px-2 py-0.5 rounded-full border border-border-heavy bg-surface/95 font-mono text-[10px] text-text-dim uppercase">
                              {item.mimeType.replace('image/', '')}
                            </div>

                            <div class="absolute bottom-1.5 left-1.5 right-1.5 flex items-center justify-between gap-2 opacity-100 md:opacity-0 md:group-hover:opacity-100 md:group-focus-within:opacity-100 transition-opacity">
                              <div class="flex items-center gap-1 pointer-events-auto">
                                <FormatButton
                                  label="URL"
                                  active={getCardFormat(item.id) === 'direct'}
                                  onClick={(event) => {
                                    event.stopPropagation()
                                    if (isDeleting()) {
                                      return
                                    }

                                    void copyLibraryItem(item, 'direct')
                                  }}
                                />
                                <FormatButton
                                  label="MD"
                                  active={getCardFormat(item.id) === 'markdown'}
                                  onClick={(event) => {
                                    event.stopPropagation()
                                    if (isDeleting()) {
                                      return
                                    }

                                    void copyLibraryItem(item, 'markdown')
                                  }}
                                />
                                <FormatButton
                                  label="BB"
                                  active={getCardFormat(item.id) === 'bbcode'}
                                  onClick={(event) => {
                                    event.stopPropagation()
                                    if (isDeleting()) {
                                      return
                                    }

                                    void copyLibraryItem(item, 'bbcode')
                                  }}
                                />
                              </div>

                              <button
                                type="button"
                                class="pointer-events-auto h-7 w-7 rounded-full border border-border-heavy bg-surface/95 text-text-dim hover:text-accent hover:border-accent transition-colors text-[13px] font-bold"
                                disabled={isDeleting()}
                                onClick={(event) => {
                                  event.stopPropagation()
                                  void deleteUploadById(item.id)
                                }}
                                aria-label="Delete upload"
                              >
                                {isDeleting() ? '...' : 'x'}
                              </button>
                            </div>
                          </div>
                        )
                      }}
                    </For>
                  </div>

                  <Show when={libraryLoadingMore()}>
                    <div class="pt-2 pb-1 text-center font-mono text-[11px] text-text-dim">
                      Loading more...
                    </div>
                  </Show>

                  <Show
                    when={!libraryNextCursor() && libraryItems().length > 0}
                  >
                    <div class="pt-2 pb-1 text-center font-mono text-[10px] uppercase tracking-[1.3px] text-text-dim">
                      End of library
                    </div>
                  </Show>
                </Show>
              </Show>
            </Show>
          </div>
        </div>

        {/* ── Upload panel (desktop: side panel, mobile: full-screen overlay) ── */}
        <Show when={uploadPanelOpen()}>
          {/* Mobile overlay backdrop */}
          <div
            class="fixed inset-0 z-50 bg-bg/80 md:hidden"
            onClick={() => setUploadPanelOpen(false)}
          />

          <div class="fixed inset-0 top-[54px] z-50 flex flex-col bg-bg md:relative md:inset-auto md:top-auto md:z-auto md:w-[400px] md:shrink-0 md:border-l-2 md:border-border md:bg-surface animate-panel-in">
            {/* Panel header */}
            <div class="flex items-center justify-between px-5 py-4 border-b-2 border-border">
              <div class="panel-label mb-0 flex-1">Upload</div>
              <button
                type="button"
                class="h-7 w-7 rounded-full border border-border-heavy bg-surface-2 text-text-dim hover:text-accent hover:border-accent transition-colors text-[13px] font-bold flex items-center justify-center"
                onClick={() => setUploadPanelOpen(false)}
                aria-label="Close upload panel"
              >
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  class="w-3.5 h-3.5 stroke-current"
                  stroke-width="2.5"
                >
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            {/* Panel body */}
            <div class="flex-1 overflow-y-auto p-5 flex flex-col gap-4">
              {/* Drop zone */}
              <div
                class={`border-2 border-dashed rounded-2xl flex flex-col items-center justify-center p-8 text-center cursor-pointer transition-all duration-200 ${
                  dragging()
                    ? 'border-accent bg-accent-dim'
                    : 'border-border-heavy bg-surface hover:border-accent hover:bg-accent-dim'
                }`}
                onDragOver={(event) => {
                  event.preventDefault()
                  setDragging(true)
                }}
                onDragLeave={(event) => {
                  event.preventDefault()
                  const nextTarget = event.relatedTarget
                  if (
                    nextTarget instanceof Node &&
                    event.currentTarget.contains(nextTarget)
                  ) {
                    return
                  }
                  setDragging(false)
                }}
                onDrop={onDrop}
                onClick={() => fileInputRef?.click()}
              >
                <div class="w-12 h-12 rounded-full bg-accent-dim border-2 border-accent/25 flex items-center justify-center mb-4">
                  <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    class="w-5 h-5 stroke-accent"
                    stroke-width="2.5"
                  >
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" />
                    <line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                </div>
                <p class="text-base font-[800] mb-1">
                  {isUploading()
                    ? uploadQueueTotal() > 1
                      ? `Uploading ${uploadQueueIndex()}/${uploadQueueTotal()}...`
                      : 'Uploading...'
                    : 'Drop image(s) or click to browse'}
                </p>
                <p class="font-mono text-[13px] text-text-dim mb-4">
                  <span class="kbd">Ctrl</span> + <span class="kbd">V</span> to
                  paste from clipboard
                </p>
                <div class="flex gap-1.5">
                  <span class="format-chip">PNG</span>
                  <span class="format-chip">JPEG</span>
                  <span class="format-chip">GIF</span>
                  <span class="format-chip">WEBP</span>
                </div>
              </div>

              {/* Upload progress */}
              <Show when={isUploading()}>
                <div class="p-3 border-2 border-border rounded-xl bg-surface">
                  <div class="flex items-center justify-between text-[11px] font-mono text-text-dim mb-2">
                    <span>
                      {previewName()}
                      <Show when={uploadQueueTotal() > 1}>
                        <span class="ml-1">
                          ({uploadQueueIndex()}/{uploadQueueTotal()})
                        </span>
                      </Show>
                    </span>
                    <span>{progress()}%</span>
                  </div>
                  <div class="h-1.5 rounded-full bg-surface-2 overflow-hidden">
                    <div
                      class="h-full bg-accent rounded-full transition-all"
                      style={{ width: `${progress()}%` }}
                    />
                  </div>
                </div>
              </Show>

              {/* Upload error */}
              <Show when={uploadError()}>
                <div class="p-3 border-2 border-accent/40 rounded-xl bg-accent-dim text-sm text-accent">
                  {uploadError()}
                </div>
              </Show>

              {/* Share output */}
              <Show when={uploadResult()}>
                {(result) => (
                  <div class="p-4 border-2 border-border rounded-xl bg-surface">
                    <p class="font-mono text-[10px] text-text-dim uppercase tracking-[1.5px] mb-3">
                      Share Output
                    </p>
                    <div class="flex flex-col gap-2">
                      <OutputRow
                        label="URL"
                        value={result().directUrl}
                        onCopy={() => {
                          void copyValue(
                            result().directUrl,
                            'Direct URL copied',
                            {
                              uploadId: result().id,
                              format: 'direct',
                              source: 'uploader',
                            },
                          )
                        }}
                      />
                      <OutputRow
                        label="MD"
                        value={result().markdown}
                        onCopy={() => {
                          void copyValue(result().markdown, 'Markdown copied', {
                            uploadId: result().id,
                            format: 'markdown',
                            source: 'uploader',
                          })
                        }}
                      />
                      <OutputRow
                        label="BB"
                        value={result().bbcode}
                        onCopy={() => {
                          void copyValue(result().bbcode, 'BBCode copied', {
                            uploadId: result().id,
                            format: 'bbcode',
                            source: 'uploader',
                          })
                        }}
                      />
                    </div>
                  </div>
                )}
              </Show>
            </div>
          </div>
        </Show>
      </div>

      {/* ── Toasts ── */}
      <div class="pointer-events-none fixed bottom-4 right-4 z-[70] flex w-[min(92vw,330px)] flex-col gap-2">
        <For each={toasts()}>
          {(toast) => (
            <div
              class={`pointer-events-auto rounded-xl border-2 px-3 py-2 text-sm font-semibold shadow-[0_10px_24px_rgba(0,0,0,0.35)] ${
                toast.tone === 'success'
                  ? 'border-mint/40 bg-mint/10 text-mint'
                  : toast.tone === 'error'
                    ? 'border-accent/45 bg-accent-dim text-accent'
                    : 'border-border-heavy bg-surface text-text'
              }`}
            >
              {toast.message}
            </div>
          )}
        </For>
      </div>
    </div>
  )
}

/* ── Shared sub-components ── */

function FormatButton(props: {
  label: string
  active: boolean
  onClick: (event: MouseEvent) => void
}) {
  return (
    <button
      type="button"
      class={`h-7 min-w-8 px-2 rounded-full border font-mono text-[10px] tracking-[0.4px] transition-colors ${
        props.active
          ? 'border-accent bg-accent text-white'
          : 'border-border-heavy bg-surface/95 text-text-dim hover:text-text'
      }`}
      onClick={props.onClick}
    >
      {props.label}
    </button>
  )
}

function OutputRow(props: {
  label: string
  value: string
  onCopy: () => void
}) {
  return (
    <div class="flex items-center gap-2 p-2 rounded-lg bg-bg border border-border">
      <span class="format-chip shrink-0">{props.label}</span>
      <p class="flex-1 font-mono text-[11px] text-text-dim truncate">
        {props.value}
      </p>
      <button
        type="button"
        class="btn btn-outline text-[11px] py-0.5 px-2.5 border-border-heavy"
        onClick={props.onCopy}
      >
        Copy
      </button>
    </div>
  )
}
