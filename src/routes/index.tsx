import { createFileRoute } from '@tanstack/solid-router'
import { For, Show, createSignal, onCleanup, onMount } from 'solid-js'

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

    setPreviewName(file.name || 'clipboard-image')
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
    if (copyStatusTimer !== undefined) {
      window.clearTimeout(copyStatusTimer)
    }
  })

  const ssCardHeights = [60, 82, 55, 72, 65, 90, 58, 76, 68, 84, 62, 74]

  return (
    <div class="pt-[54px] min-h-screen flex flex-col">
      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept="image/png,image/jpeg,image/gif,image/webp"
        class="hidden"
        onChange={onInputFileSelect}
      />

      {/* Band 1: Hero */}
      <div
        class="px-7 py-7 border-b-2 border-border flex items-end justify-between gap-6 flex-wrap bg-surface animate-slide-up"
      >
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
            <div class="text-[22px] font-[800] text-secondary tracking-[-0.5px]">&lt;2s</div>
            <div class="font-mono text-[10px] text-text-dim uppercase tracking-[1px]">Paste to link</div>
          </div>
          <div class="text-center px-4 py-2.5 bg-surface-2 border-2 border-border-heavy rounded-[14px]">
            <div class="text-[22px] font-[800] text-secondary tracking-[-0.5px]">15MB</div>
            <div class="font-mono text-[10px] text-text-dim uppercase tracking-[1px]">Max upload</div>
          </div>
        </div>
      </div>

      {/* Band 2: Screenshot + Upload */}
      <div class="flex-1 grid grid-cols-1 md:grid-cols-[1.3fr_1fr] min-h-0">
        {/* Left: Screenshot panel */}
        <div class="p-6 flex flex-col border-r-0 md:border-r-2 border-b-2 md:border-b-0 border-border bg-surface animate-slide-up [animation-delay:80ms]">
          <div class="panel-label">How it works</div>
          <div class="flex-1 min-h-[300px] bg-bg border-2 border-border-heavy rounded-2xl overflow-hidden shadow-[0_8px_32px_rgba(0,0,0,0.3)]">
            {/* Faux browser chrome */}
            <div class="h-[34px] bg-surface-2 border-b-2 border-border flex items-center px-3.5 gap-1.5">
              <div class="w-[9px] h-[9px] rounded-full bg-accent" />
              <div class="w-[9px] h-[9px] rounded-full bg-secondary" />
              <div class="w-[9px] h-[9px] rounded-full bg-mint" />
              <div class="ml-2.5 h-4 w-[140px] bg-bg border border-border rounded-full" />
            </div>
            {/* Faux masonry grid */}
            <div class="p-3 grid grid-cols-[repeat(auto-fill,minmax(80px,1fr))] gap-2 h-[calc(100%-34px)] content-start">
              <For each={ssCardHeights}>
                {(height, i) => (
                  <div
                    class={`rounded-[10px] border-2 bg-surface-2 ${
                      i() === 2
                        ? 'opacity-100 border-accent bg-accent-dim relative'
                        : 'opacity-40 border-border'
                    } ${i() >= 6 ? 'max-md:hidden' : ''}`}
                    style={{ height: `${height}px` }}
                  >
                    <Show when={i() === 2}>
                      <span class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 font-display text-[9px] font-[800] tracking-[1px] text-accent">
                        COPIED!
                      </span>
                    </Show>
                  </div>
                )}
              </For>
            </div>
          </div>
          <p class="font-mono text-[11px] text-text-dim text-center mt-3 italic">
            Replace with a real GIF showing click-to-copy in action
          </p>
        </div>

        {/* Right: Upload panel */}
        <div class="p-6 flex flex-col animate-slide-up [animation-delay:160ms]">
          <div class="panel-label">Drop zone</div>

          {/* Drop target */}
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
            {/* Upload icon */}
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
              <span class="kbd">Ctrl</span> + <span class="kbd">V</span> to paste from clipboard
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

          {/* Error */}
          <Show when={uploadError()}>
            <div class="mt-3 p-3 border-2 border-accent/40 rounded-xl bg-accent-dim text-sm text-accent">
              {uploadError()}
            </div>
          </Show>

          {/* Copy status toast */}
          <Show when={copyStatus()}>
            <div class="mt-3 p-3 border-2 border-mint/30 rounded-xl bg-mint/5 text-sm text-mint">
              {copyStatus()}
            </div>
          </Show>

          {/* Share output */}
          <Show when={uploadResult()}>
            {(result) => (
              <div class="mt-3 p-4 border-2 border-border rounded-xl bg-surface">
                <p class="font-mono text-[10px] text-text-dim uppercase tracking-[1.5px] mb-3">Share Output</p>
                <div class="flex flex-col gap-2">
                  <OutputRow
                    label="URL"
                    value={result().directUrl}
                    onCopy={() => { void copyValue(result().directUrl, 'Direct URL copied') }}
                  />
                  <OutputRow
                    label="MD"
                    value={result().markdown}
                    onCopy={() => { void copyValue(result().markdown, 'Markdown copied') }}
                  />
                  <OutputRow
                    label="BB"
                    value={result().bbcode}
                    onCopy={() => { void copyValue(result().bbcode, 'BBCode copied') }}
                  />
                </div>
              </div>
            )}
          </Show>

          {/* Feature checklist */}
          <div class="mt-4 flex flex-col gap-2">
            <div class="flex items-center gap-2.5 text-[13px] font-semibold text-text-dim p-2.5 px-3.5 bg-surface border-2 border-border rounded-xl transition-all hover:border-border-heavy">
              <div class="w-[22px] h-[22px] rounded-full bg-accent-dim flex items-center justify-center shrink-0">
                <svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" class="w-[11px] h-[11px] stroke-accent stroke-[3]">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              One click = link copied to clipboard
            </div>
            <div class="flex items-center gap-2.5 text-[13px] font-semibold text-text-dim p-2.5 px-3.5 bg-surface border-2 border-border rounded-xl transition-all hover:border-border-heavy">
              <div class="w-[22px] h-[22px] rounded-full bg-accent-dim flex items-center justify-center shrink-0">
                <svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" class="w-[11px] h-[11px] stroke-accent stroke-[3]">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              URL, Markdown, and BBCode formats
            </div>
            <div class="flex items-center gap-2.5 text-[13px] font-semibold text-text-dim p-2.5 px-3.5 bg-surface border-2 border-border rounded-xl transition-all hover:border-border-heavy">
              <div class="w-[22px] h-[22px] rounded-full bg-accent-dim flex items-center justify-center shrink-0">
                <svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round" class="w-[11px] h-[11px] stroke-accent stroke-[3]">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              Sign in to keep a permanent collection
            </div>
          </div>
        </div>
      </div>
    </div>
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
