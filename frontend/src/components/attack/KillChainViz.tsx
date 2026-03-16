import type { KillChain } from '@/types'

const stepConfig = {
  deploy: { color: 'border-green bg-green-dim text-green', label: 'Deploy', desc: 'Attacker deploys exploit contract' },
  lure: { color: 'border-yellow bg-yellow-dim text-yellow', label: 'Lure', desc: 'Bot interacts with bait pool/token' },
  drain: { color: 'border-red bg-red-dim text-red', label: 'Drain', desc: 'Funds extracted from victim bot' },
}

function shortAddr(addr: string) {
  if (!addr) return null
  return `${addr.slice(0, 6)}...${addr.slice(-4)}`
}

interface Props {
  killChain: KillChain
}

export default function KillChainViz({ killChain }: Props) {
  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-4">Kill Chain</h3>

      <div className="flex items-center gap-2 overflow-x-auto pb-2">
        {killChain.steps.map((step, i) => {
          const cfg = stepConfig[step.action] ?? stepConfig.drain
          return (
            <div key={i} className="flex items-center gap-2">
              <div className={`border-2 rounded-lg p-3 min-w-[180px] ${cfg.color}`}>
                <p className="font-bold text-sm mb-1">{cfg.label}</p>
                <p className="text-xs opacity-60 mb-2">{cfg.desc}</p>
                <p className="text-xs opacity-80">Block {step.block}</p>
                {step.contract && (
                  <p className="text-xs mt-1">
                    <a
                      href={`https://etherscan.io/address/${step.contract}`}
                      target="_blank"
                      rel="noreferrer"
                      className="underline opacity-70 hover:opacity-100 font-mono"
                    >
                      {shortAddr(step.contract)}
                    </a>
                  </p>
                )}
                {step.target && (
                  <p className="text-xs mt-1 opacity-70">
                    &rarr;{' '}
                    <a
                      href={`https://etherscan.io/address/${step.target}`}
                      target="_blank"
                      rel="noreferrer"
                      className="underline hover:opacity-100 font-mono"
                    >
                      {shortAddr(step.target)}
                    </a>
                  </p>
                )}
                {step.tx && (
                  <a
                    href={`https://etherscan.io/tx/${step.tx}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs underline opacity-70 hover:opacity-100 break-all block mt-1"
                  >
                    tx: {step.tx.slice(0, 10)}...
                  </a>
                )}
                {step.amount && <p className="text-xs mt-1 font-bold">{step.amount}</p>}
              </div>
              {i < killChain.steps.length - 1 && (
                <span className="text-muted text-lg shrink-0">&rarr;</span>
              )}
            </div>
          )
        })}
      </div>

      <div className="mt-4 flex items-center gap-4 text-xs text-muted">
        <span>Total Loss: <strong className="text-red">{killChain.total_loss}</strong></span>
        <span>Detection Window: <strong className="text-yellow">{killChain.detection_window}</strong></span>
      </div>
    </div>
  )
}
