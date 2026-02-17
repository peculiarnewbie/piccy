import { createFileRoute } from '@tanstack/solid-router'
import { Show, createSignal, onCleanup, onMount } from 'solid-js'

export const Route = createFileRoute('/')({ component: App })

type UploadPayload = {
  id: string
  directUrl: string
  markdown: string
  bbcode: string
}

const MAX_SIZE_BYTES = 15 * 1024 * 1024
const UPLOAD_REQUEST_TIMEOUT_MS = 90_000

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
      reject(new Error('Network error while uploading.'))
    }

    request.onabort = () => {
      reject(new Error('Upload was cancelled. Please try again.'))
    }

    request.ontimeout = () => {
      reject(new Error('Upload timed out while waiting for server response.'))
    }

    request.onload = () => {
      if (request.status < 200 || request.status >= 300) {
        reject(
          new Error(parseUploadError(request.status, request.responseText)),
        )
        return
      }

      try {
        const payload = JSON.parse(request.responseText) as UploadPayload
        resolve(payload)
      } catch {
        reject(new Error('Upload succeeded but response parsing failed.'))
      }
    }

    request.send(formData)
  })
}

const copyToClipboard = async (value: string): Promise<void> => {
  if (navigator.clipboard?.writeText) {
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

function App() {
  const [dragging, setDragging] = createSignal(false)
  const [isUploading, setIsUploading] = createSignal(false)
  const [progress, setProgress] = createSignal(0)
  const [uploadError, setUploadError] = createSignal('')
  const [uploadResult, setUploadResult] = createSignal<UploadPayload | null>(
    null,
  )
  const [previewUrl, setPreviewUrl] = createSignal<string | null>(null)
  const [previewName, setPreviewName] = createSignal('')
  const [copyStatus, setCopyStatus] = createSignal('')

  let fileInputRef: HTMLInputElement | undefined
  let copyStatusTimer: number | undefined

  const setTemporaryCopyStatus = (value: string) => {
    setCopyStatus(value)

    if (copyStatusTimer !== undefined) {
      window.clearTimeout(copyStatusTimer)
    }

    copyStatusTimer = window.setTimeout(() => {
      setCopyStatus('')
      copyStatusTimer = undefined
    }, 1600)
  }

  const copyValue = async (value: string, label: string) => {
    try {
      await copyToClipboard(value)
      setTemporaryCopyStatus(label)
    } catch {
      setTemporaryCopyStatus('Copy failed. Please copy manually.')
    }
  }

  const setNextPreview = (file: File) => {
    const currentPreviewUrl = previewUrl()
    if (currentPreviewUrl) {
      URL.revokeObjectURL(currentPreviewUrl)
    }

    setPreviewUrl(URL.createObjectURL(file))
    setPreviewName(file.name || 'clipboard-image')
  }

  const startUpload = async (file: File) => {
    setUploadError('')
    setUploadResult(null)
    setCopyStatus('')

    if (!file.type.startsWith('image/')) {
      setUploadError('Please choose an image file.')
      return
    }

    if (file.size > MAX_SIZE_BYTES) {
      setUploadError('File too large. Maximum upload size is 15 MB.')
      return
    }

    setNextPreview(file)
    setProgress(0)
    setIsUploading(true)

    try {
      const payload = await uploadWithProgress(file, setProgress)
      setUploadResult(payload)
      void copyValue(payload.directUrl, 'Direct URL copied')
    } catch (error) {
      setUploadError(
        error instanceof Error ? error.message : 'Upload failed unexpectedly.',
      )
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

  onMount(() => {
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

    window.addEventListener('paste', handlePaste)

    onCleanup(() => {
      window.removeEventListener('paste', handlePaste)
    })
  })

  onCleanup(() => {
    const currentPreviewUrl = previewUrl()
    if (currentPreviewUrl) {
      URL.revokeObjectURL(currentPreviewUrl)
    }

    if (copyStatusTimer !== undefined) {
      window.clearTimeout(copyStatusTimer)
    }
  })

  return (
    <main class="min-h-screen bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950 px-4 py-8 md:px-8 md:py-12 text-slate-100">
      <section class="mx-auto max-w-5xl space-y-6">
        <div class="space-y-3 text-center">
          <p class="text-xs uppercase tracking-[0.28em] text-cyan-300">
            Piccy Upload
          </p>
          <h1 class="text-3xl font-semibold md:text-5xl">
            Paste, drop, or click. Share instantly.
          </h1>
          <p class="mx-auto max-w-2xl text-sm text-slate-300 md:text-base">
            Press Ctrl+V or Cmd+V anytime on this page to upload from your
            clipboard. Anonymous uploads expire after 30 days.
          </p>
        </div>

        <div
          class={`rounded-2xl border border-dashed p-7 transition-all md:p-10 ${
            dragging()
              ? 'border-cyan-300 bg-cyan-300/10'
              : 'border-slate-600 bg-slate-900/70'
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
        >
          <input
            ref={fileInputRef}
            type="file"
            accept="image/png,image/jpeg,image/gif,image/webp"
            class="hidden"
            onChange={onInputFileSelect}
          />

          <div class="flex flex-col items-center gap-4 text-center">
            <button
              type="button"
              class="rounded-lg bg-cyan-500 px-6 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
              onClick={() => fileInputRef?.click()}
              disabled={isUploading()}
            >
              {isUploading() ? 'Uploading...' : 'Choose image'}
            </button>
            <p class="text-sm text-slate-300">
              or drag-and-drop an image file here
            </p>
            <p class="text-xs text-slate-400">
              PNG, JPEG, GIF, WEBP up to 15 MB
            </p>
          </div>
        </div>

        <Show when={isUploading()}>
          <div class="rounded-xl border border-slate-700 bg-slate-900/80 p-4">
            <div class="mb-2 flex items-center justify-between text-xs text-slate-300">
              <span>Uploading {previewName()}</span>
              <span>{progress()}%</span>
            </div>
            <div class="h-2 overflow-hidden rounded-full bg-slate-700">
              <div
                class="h-full bg-cyan-400 transition-all"
                style={{ width: `${progress()}%` }}
              />
            </div>
          </div>
        </Show>

        <Show when={uploadError()}>
          <div class="rounded-xl border border-red-500/50 bg-red-950/40 p-4 text-sm text-red-200">
            {uploadError()}
          </div>
        </Show>

        <Show when={copyStatus()}>
          <div class="rounded-xl border border-emerald-500/50 bg-emerald-950/40 p-3 text-sm text-emerald-200">
            {copyStatus()}
          </div>
        </Show>

        <Show when={previewUrl()}>
          {(currentPreviewUrl) => (
            <figure class="overflow-hidden rounded-2xl border border-slate-700 bg-slate-900/80">
              <img
                src={currentPreviewUrl()}
                alt="Upload preview"
                class="max-h-[30rem] w-full object-contain"
              />
            </figure>
          )}
        </Show>

        <Show when={uploadResult()}>
          {(result) => (
            <div class="rounded-2xl border border-slate-700 bg-slate-900/80 p-5 md:p-6">
              <p class="mb-4 text-xs uppercase tracking-[0.2em] text-cyan-300">
                Share Output
              </p>
              <div class="space-y-4">
                <OutputRow
                  label="Direct URL"
                  value={result().directUrl}
                  onCopy={() => {
                    void copyValue(result().directUrl, 'Direct URL copied')
                  }}
                />
                <OutputRow
                  label="Markdown"
                  value={result().markdown}
                  onCopy={() => {
                    void copyValue(result().markdown, 'Markdown copied')
                  }}
                />
                <OutputRow
                  label="BBCode"
                  value={result().bbcode}
                  onCopy={() => {
                    void copyValue(result().bbcode, 'BBCode copied')
                  }}
                />
              </div>
            </div>
          )}
        </Show>
      </section>
    </main>
  )
}

function OutputRow(props: {
  label: string
  value: string
  onCopy: () => void
}) {
  return (
    <div class="rounded-xl border border-slate-700 bg-slate-950/50 p-3">
      <div class="mb-2 flex items-center justify-between gap-3">
        <p class="text-sm font-medium text-slate-200">{props.label}</p>
        <button
          type="button"
          class="rounded-md border border-slate-500 px-3 py-1 text-xs font-semibold text-slate-100 transition hover:border-cyan-300 hover:text-cyan-200"
          onClick={props.onCopy}
        >
          Copy
        </button>
      </div>
      <p class="break-all rounded-md bg-slate-900/90 px-3 py-2 font-mono text-xs text-slate-300">
        {props.value}
      </p>
    </div>
  )
}
