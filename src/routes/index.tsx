import { createFileRoute } from '@tanstack/solid-router'
import { For, Show, createSignal, onCleanup, onMount } from 'solid-js'

export const Route = createFileRoute('/')({ component: App })

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

type CopyTrackingInput = {
  uploadId: string
  format: CopyFormat
  source: CopySource
}

const MAX_SIZE_BYTES = 15 * 1024 * 1024
const UPLOAD_REQUEST_TIMEOUT_MS = 90_000
const UPLOAD_MAX_ATTEMPTS = 2

const LIBRARY_SKELETON_HEIGHTS = [
  74, 122, 98, 146, 84, 136, 112, 158, 92, 128, 104, 150,
]

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
): Promise<UploadPayload> => {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest()
    const formData = new FormData()

    formData.append('file', file)
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
): Promise<UploadPayload> => {
  let attempt = 0

  while (attempt < UPLOAD_MAX_ATTEMPTS) {
    try {
      return await uploadWithProgress(file, onProgress)
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

function App() {
  const [dragging, setDragging] = createSignal(false)
  const [isUploading, setIsUploading] = createSignal(false)
  const [progress, setProgress] = createSignal(0)
  const [uploadError, setUploadError] = createSignal('')
  const [uploadResult, setUploadResult] = createSignal<UploadPayload | null>(
    null,
  )
  const [previewName, setPreviewName] = createSignal('')

  const [libraryItems, setLibraryItems] = createSignal<Array<LibraryItem>>([])
  const [libraryNextCursor, setLibraryNextCursor] = createSignal<string | null>(
    null,
  )
  const [libraryError, setLibraryError] = createSignal('')
  const [libraryLoadingInitial, setLibraryLoadingInitial] = createSignal(true)
  const [libraryLoadingMore, setLibraryLoadingMore] = createSignal(false)

  const [cardFormats, setCardFormats] = createSignal<
    Partial<Record<string, CopyFormat>>
  >({})
  const [copiedCardId, setCopiedCardId] = createSignal<string | null>(null)
  const [deletingById, setDeletingById] = createSignal<
    Partial<Record<string, true>>
  >({})
  const [focusedIndex, setFocusedIndex] = createSignal(-1)

  const [toasts, setToasts] = createSignal<Array<ToastEntry>>([])

  const cardRefs = new Map<string, HTMLDivElement>()

  let fileInputRef: HTMLInputElement | undefined
  let libraryScrollRef: HTMLDivElement | undefined
  let copiedCardTimer: number | undefined

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

  const getCardFormat = (uploadId: string): CopyFormat => {
    return cardFormats()[uploadId] ?? 'direct'
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

      if (tracking) {
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
    await copyValue(getFormatValue(item, format), getFormatLabel(format), {
      uploadId: item.id,
      format,
      source: 'library',
    })
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

  const startUpload = async (file: File) => {
    if (isUploading()) {
      pushToast('info', 'Upload in progress. Please wait for it to finish.')
      return
    }

    setUploadError('')
    setUploadResult(null)

    if (!file.type.startsWith('image/')) {
      setUploadError('Please choose an image file.')
      return
    }

    if (file.size > MAX_SIZE_BYTES) {
      setUploadError('File too large. Maximum upload size is 15 MB.')
      return
    }

    setPreviewName(file.name || 'clipboard-image')
    setProgress(0)
    setIsUploading(true)

    try {
      const payload = await uploadWithRetry(file, setProgress)
      setUploadResult(payload)
      await copyValue(payload.directUrl, 'Direct URL copied', {
        uploadId: payload.id,
        format: 'direct',
        source: 'uploader',
      })
      await reloadLibrary()
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Upload failed unexpectedly.'
      setUploadError(message)
      pushToast('error', message)
    } finally {
      setIsUploading(false)
      setProgress(100)
    }
  }

  const onInputFileSelect = (event: Event) => {
    const currentTarget = event.currentTarget as HTMLInputElement
    const selectedFile = currentTarget.files?.item(0)
    currentTarget.value = ''

    if (!selectedFile) {
      return
    }

    void startUpload(selectedFile)
  }

  const onDrop = (event: DragEvent) => {
    event.preventDefault()
    setDragging(false)

    const selectedFile =
      event.dataTransfer?.files && event.dataTransfer.files.length > 0
        ? event.dataTransfer.files.item(0)
        : null

    if (!selectedFile) {
      return
    }

    void startUpload(selectedFile)
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

  onMount(() => {
    void reloadLibrary()

    const handlePaste = (event: ClipboardEvent) => {
      const items = event.clipboardData?.items
      if (!items) {
        return
      }

      for (const item of items) {
        if (!item.type.startsWith('image/')) {
          continue
        }

        const pastedFile = item.getAsFile()
        if (!pastedFile) {
          continue
        }

        event.preventDefault()
        void startUpload(pastedFile)
        break
      }
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

    window.addEventListener('paste', handlePaste)
    window.addEventListener('keydown', handleWindowKeyDown)

    onCleanup(() => {
      window.removeEventListener('paste', handlePaste)
      window.removeEventListener('keydown', handleWindowKeyDown)
    })
  })

  onCleanup(() => {
    if (copiedCardTimer !== undefined) {
      window.clearTimeout(copiedCardTimer)
    }
  })

  return (
    <div class="pt-[54px] min-h-screen flex flex-col">
      <input
        ref={fileInputRef}
        type="file"
        accept="image/png,image/jpeg,image/gif,image/webp"
        class="hidden"
        onChange={onInputFileSelect}
      />

      <div class="px-7 py-7 border-b-2 border-border flex items-end justify-between gap-6 flex-wrap bg-surface animate-slide-up">
        <div>
          <h1 class="text-[clamp(22px,3.5vw,30px)] font-[800] tracking-[-0.8px] mb-1 leading-[1.2]">
            Grab, drop, share. <em class="italic text-accent">Repeat.</em>
          </h1>
          <p class="font-mono text-sm text-text-dim">
            A clipboard for your images. Click any to copy its link.
          </p>
        </div>
        <div class="flex gap-4 shrink-0 max-md:hidden">
          <div class="text-center px-4 py-2.5 bg-surface-2 border-2 border-border-heavy rounded-[14px]">
            <div class="text-[22px] font-[800] text-secondary tracking-[-0.5px]">
              &lt;2s
            </div>
            <div class="font-mono text-[10px] text-text-dim uppercase tracking-[1px]">
              Paste to link
            </div>
          </div>
          <div class="text-center px-4 py-2.5 bg-surface-2 border-2 border-border-heavy rounded-[14px]">
            <div class="text-[22px] font-[800] text-secondary tracking-[-0.5px]">
              15MB
            </div>
            <div class="font-mono text-[10px] text-text-dim uppercase tracking-[1px]">
              Max upload
            </div>
          </div>
        </div>
      </div>

      <div class="flex-1 grid grid-cols-1 md:grid-cols-[1.3fr_1fr] min-h-0">
        <div class="p-6 flex flex-col border-r-0 md:border-r-2 border-b-2 md:border-b-0 border-border bg-surface animate-slide-up [animation-delay:80ms]">
          <div class="panel-label">How it works</div>
          <div class="flex-1 min-h-[300px] bg-bg border-2 border-border-heavy rounded-2xl overflow-hidden shadow-[0_8px_32px_rgba(0,0,0,0.3)]">
            <div class="h-[34px] bg-surface-2 border-b-2 border-border flex items-center px-3.5 gap-1.5">
              <div class="w-[9px] h-[9px] rounded-full bg-accent" />
              <div class="w-[9px] h-[9px] rounded-full bg-secondary" />
              <div class="w-[9px] h-[9px] rounded-full bg-mint" />
              <div class="ml-2.5 h-4 w-[140px] bg-bg border border-border rounded-full" />
            </div>

            <div
              ref={libraryScrollRef}
              class="p-3 h-[calc(100%-34px)] overflow-y-auto"
              onScroll={maybeLoadNextPageFromScroll}
            >
              <Show
                when={!libraryLoadingInitial()}
                fallback={
                  <div class="columns-2 md:columns-3 gap-2 [column-fill:_balance]">
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
                          <p class="text-base font-[800] mb-1">
                            No uploads yet
                          </p>
                          <p class="font-mono text-[12px] text-text-dim">
                            Paste, drop, or click upload to add your first
                            image.
                          </p>
                        </div>
                      </div>
                    }
                  >
                    <div class="columns-2 md:columns-3 gap-2 [column-fill:_balance]">
                      <For each={libraryItems()}>
                        {(item, index) => {
                          const isFocused = () => focusedIndex() === index()
                          const isCopied = () => copiedCardId() === item.id
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

                                void copyLibraryItem(
                                  item,
                                  getCardFormat(item.id),
                                )
                              }}
                              onKeyDown={(event) => {
                                if (
                                  event.key === 'Enter' ||
                                  event.key === ' '
                                ) {
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
                                    active={
                                      getCardFormat(item.id) === 'markdown'
                                    }
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

          <p class="font-mono text-[11px] text-text-dim text-center mt-3 italic">
            Replace with a real GIF showing click-to-copy in action
          </p>
        </div>

        <div class="p-6 flex flex-col animate-slide-up [animation-delay:160ms]">
          <div class="panel-label">Drop zone</div>

          <div
            class={`flex-1 border-2 border-dashed rounded-2xl flex flex-col items-center justify-center p-8 text-center cursor-pointer transition-all duration-200 ${
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
              {isUploading() ? 'Uploading...' : 'Drop image or click to browse'}
            </p>
            <p class="font-mono text-[13px] text-text-dim mb-5">
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

          <Show when={isUploading()}>
            <div class="mt-3 p-3 border-2 border-border rounded-xl bg-surface">
              <div class="flex items-center justify-between text-[11px] font-mono text-text-dim mb-2">
                <span>{previewName()}</span>
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

          <Show when={uploadError()}>
            <div class="mt-3 p-3 border-2 border-accent/40 rounded-xl bg-accent-dim text-sm text-accent">
              {uploadError()}
            </div>
          </Show>

          <Show when={uploadResult()}>
            {(result) => (
              <div class="mt-3 p-4 border-2 border-border rounded-xl bg-surface">
                <p class="font-mono text-[10px] text-text-dim uppercase tracking-[1.5px] mb-3">
                  Share Output
                </p>
                <div class="flex flex-col gap-2">
                  <OutputRow
                    label="URL"
                    value={result().directUrl}
                    onCopy={() => {
                      void copyValue(result().directUrl, 'Direct URL copied', {
                        uploadId: result().id,
                        format: 'direct',
                        source: 'uploader',
                      })
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

          <div class="mt-4 flex flex-col gap-2">
            <div class="flex items-center gap-2.5 text-[13px] font-semibold text-text-dim p-2.5 px-3.5 bg-surface border-2 border-border rounded-xl transition-all hover:border-border-heavy">
              <div class="w-[22px] h-[22px] rounded-full bg-accent-dim flex items-center justify-center shrink-0">
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  class="w-[11px] h-[11px] stroke-accent stroke-[3]"
                >
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              One click = link copied to clipboard
            </div>
            <div class="flex items-center gap-2.5 text-[13px] font-semibold text-text-dim p-2.5 px-3.5 bg-surface border-2 border-border rounded-xl transition-all hover:border-border-heavy">
              <div class="w-[22px] h-[22px] rounded-full bg-accent-dim flex items-center justify-center shrink-0">
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  class="w-[11px] h-[11px] stroke-accent stroke-[3]"
                >
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              URL, Markdown, and BBCode formats
            </div>
            <div class="flex items-center gap-2.5 text-[13px] font-semibold text-text-dim p-2.5 px-3.5 bg-surface border-2 border-border rounded-xl transition-all hover:border-border-heavy">
              <div class="w-[22px] h-[22px] rounded-full bg-accent-dim flex items-center justify-center shrink-0">
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  class="w-[11px] h-[11px] stroke-accent stroke-[3]"
                >
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              Sign in to keep a permanent collection
            </div>
          </div>
        </div>
      </div>

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
