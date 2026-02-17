import { Link, createFileRoute } from '@tanstack/solid-router'

export const Route = createFileRoute('/pricing')({
  component: PricingRoute,
})

function PricingRoute() {
  return (
    <div class="min-h-screen pt-[54px] flex items-center justify-center px-5 py-12 animate-route-enter">
      {/* Ambient glow behind the card */}
      <div class="absolute inset-0 pointer-events-none overflow-hidden">
        <div class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-accent/[0.04] blur-[120px]" />
      </div>

      <div class="relative w-full max-w-[400px]">
        <p class="text-center font-mono text-[12px] text-text-dim mb-5">
          2 cents a day. Your couch has more.
        </p>

        {/* Decorative corner accents */}
        <div class="absolute -top-px -left-px w-6 h-6 border-t-2 border-l-2 border-accent/50 rounded-tl-2xl pointer-events-none" />
        <div class="absolute -top-px -right-px w-6 h-6 border-t-2 border-r-2 border-accent/50 rounded-tr-2xl pointer-events-none" />
        <div class="absolute -bottom-px -left-px w-6 h-6 border-b-2 border-l-2 border-accent/50 rounded-bl-2xl pointer-events-none" />
        <div class="absolute -bottom-px -right-px w-6 h-6 border-b-2 border-r-2 border-accent/50 rounded-br-2xl pointer-events-none" />

        <div class="border-2 border-border-heavy rounded-2xl bg-surface overflow-hidden shadow-[0_20px_60px_rgba(0,0,0,0.45),0_0_0_1px_rgba(255,107,107,0.06)]">
          {/* Header */}
          <div class="px-7 pt-8 pb-6 text-center border-b-2 border-border">
            <div class="inline-block px-3 py-1 rounded-full border border-border-heavy bg-surface-2 font-mono text-[10px] uppercase tracking-[1.5px] text-text-dim mb-5">
              One plan. That's it.
            </div>

            <div class="flex items-baseline justify-center gap-1.5">
              <span class="text-[52px] font-[800] tracking-[-2.5px] leading-none text-text">
                $8
              </span>
              <span class="font-mono text-[13px] text-text-dim">/ year</span>
            </div>

            <div class="mt-3 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-mint/[0.08] border border-mint/20">
              <span class="font-mono text-[12px] text-mint font-medium">$0.67/mo</span>
              <span class="font-mono text-[11px] text-text-dim">— billed yearly</span>
            </div>
          </div>

          {/* Features */}
          <div class="px-7 py-6 flex flex-col gap-3.5">
            <FeatureRow
              icon="stack"
              label="Up to 10,000 images"
              detail="More than enough for years"
            />
            <FeatureRow
              icon="infinity"
              label="Images stay forever"
              detail="No expiration, no deletion"
            />
            <FeatureRow
              icon="folder"
              label="Organizing tools"
              detail="Folders, tags, and search"
            />
          </div>

          {/* CTA */}
          <div class="px-7 pb-8 pt-2">
            <button
              type="button"
              class="w-full py-3.5 rounded-xl bg-accent text-white font-[800] text-[15px] tracking-[-0.2px] border-2 border-accent cursor-pointer transition-all duration-200 hover:translate-y-[-2px] hover:shadow-[0_8px_28px_rgba(255,107,107,0.35)] active:translate-y-0 active:shadow-none"
            >
              Get Piccy
            </button>
            <p class="text-center font-mono text-[11px] text-text-dim mt-3">
              Cancel anytime. No questions asked.
            </p>
          </div>
        </div>

        {/* Below card */}
        <div class="text-center mt-6">
          <Link
            to="/"
            class="font-mono text-[12px] text-text-dim hover:text-accent transition-colors no-underline"
          >
            &larr; Back to uploading
          </Link>
        </div>
      </div>
    </div>
  )
}

function FeatureRow(props: { icon: string; label: string; detail: string }) {
  return (
    <div class="flex items-start gap-3.5 group">
      <div class="mt-0.5 w-8 h-8 rounded-lg bg-accent-dim border border-accent/20 flex items-center justify-center shrink-0 transition-colors group-hover:border-accent/40">
        <FeatureIcon type={props.icon} />
      </div>
      <div>
        <p class="text-[14px] font-[700] leading-snug">{props.label}</p>
        <p class="font-mono text-[11px] text-text-dim mt-0.5">{props.detail}</p>
      </div>
    </div>
  )
}

function FeatureIcon(props: { type: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke-linecap="round"
      stroke-linejoin="round"
      class="w-[14px] h-[14px] stroke-accent stroke-[2.5]"
    >
      {props.type === 'stack' && (
        <>
          <rect x="3" y="3" width="7" height="7" rx="1" />
          <rect x="14" y="3" width="7" height="7" rx="1" />
          <rect x="3" y="14" width="7" height="7" rx="1" />
          <rect x="14" y="14" width="7" height="7" rx="1" />
        </>
      )}
      {props.type === 'infinity' && (
        <path d="M18.178 8c5.096 0 5.096 8 0 8-5.095 0-7.133-8-12.739-8-4.585 0-4.585 8 0 8 5.606 0 7.644-8 12.74-8z" />
      )}
      {props.type === 'folder' && (
        <>
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
        </>
      )}
    </svg>
  )
}
