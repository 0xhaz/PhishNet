import type { KillChainStep } from '@/types'

const actionConfig = {
  deploy: { color: 'bg-green text-bg', contractLabel: 'Exploit Contract', targetLabel: '' },
  lure: { color: 'bg-yellow text-bg', contractLabel: 'Bait Pool/Source', targetLabel: 'Victim Bot' },
  drain: { color: 'bg-red text-bg', contractLabel: 'Victim Bot', targetLabel: 'Funds Sent To' },
}

interface Props {
  steps: KillChainStep[]
}

export default function TxFlowPanel({ steps }: Props) {
  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-4">Transaction Flow</h3>
      <div className="relative pl-6">
        <div className="absolute left-[11px] top-2 bottom-2 w-px bg-border" />
        {steps.map((step, i) => {
          const cfg = actionConfig[step.action] ?? { color: 'bg-muted text-bg', contractLabel: 'Contract', targetLabel: 'Target' }
          return (
            <div key={i} className="relative mb-6 last:mb-0">
              <div className={`absolute -left-6 top-0.5 w-5 h-5 rounded-full flex items-center justify-center text-xs font-bold ${cfg.color}`}>
                {step.step}
              </div>
              <div className="ml-2">
                <p className="font-bold text-sm capitalize">{step.action}</p>
                <div className="text-xs text-muted mt-1 space-y-0.5">
                  <p>Block: <span className="text-text">{step.block}</span></p>
                  {step.tx && (
                    <p>
                      Tx:{' '}
                      <a
                        href={`https://etherscan.io/tx/${step.tx}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue hover:underline font-mono"
                      >
                        {step.tx.slice(0, 16)}...
                      </a>
                    </p>
                  )}
                  {step.amount && <p>Amount: <span className="text-red font-bold">{step.amount}</span></p>}
                  {step.contract && (
                    <p>
                      {cfg.contractLabel}:{' '}
                      <a
                        href={`https://etherscan.io/address/${step.contract}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue hover:underline font-mono"
                      >
                        {step.contract.slice(0, 10)}...
                      </a>
                    </p>
                  )}
                  {step.target && cfg.targetLabel && (
                    <p>
                      {cfg.targetLabel}:{' '}
                      <a
                        href={`https://etherscan.io/address/${step.target}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-blue hover:underline font-mono"
                      >
                        {step.target.slice(0, 10)}...
                      </a>
                    </p>
                  )}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
