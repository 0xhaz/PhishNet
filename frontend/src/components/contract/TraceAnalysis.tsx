import { useEffect, useState } from 'react'
import { traceAnalyze } from '@/api/client'
import type { TraceAnalysis as TraceAnalysisData } from '@/api/client'

interface Props {
  address: string
}

function riskColor(level: string) {
  switch (level) {
    case 'high': return 'bg-red/20 text-red border-red/40'
    case 'medium': return 'bg-yellow/20 text-yellow border-yellow/40'
    default: return 'bg-green/20 text-green border-green/40'
  }
}

function scoreBg(score: number) {
  if (score >= 60) return 'bg-red/20 text-red'
  if (score >= 30) return 'bg-yellow/20 text-yellow'
  return 'bg-green/20 text-green'
}

export default function TraceAnalysis({ address }: Props) {
  const [data, setData] = useState<TraceAnalysisData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    traceAnalyze(address)
      .then(setData)
      .catch(() => null)
      .finally(() => setLoading(false))
  }, [address])

  if (loading) {
    return (
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Trace-Guided Analysis</h3>
        <div className="flex items-center gap-2 text-sm text-muted">
          <span className="inline-block w-3 h-3 border-2 border-blue border-t-transparent rounded-full animate-spin" />
          Fetching transaction history and cross-referencing with bytecode...
        </div>
      </div>
    )
  }

  if (!data || (data.total_transactions === 0 && data.traced_selectors.length === 0)) {
    return (
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">
          Trace-Guided Analysis
          <span className="text-[10px] text-muted font-normal ml-2">SKANF Trace</span>
        </h3>
        <p className="text-muted text-sm">No transaction history available for trace analysis.</p>
      </div>
    )
  }

  const calledSelectors = data.traced_selectors.filter(ts => ts.call_count > 0)
  const uncalledSelectors = data.traced_selectors.filter(ts => ts.call_count === 0 && ts.in_bytecode)

  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider">
          Trace-Guided Analysis
          <span className="text-[10px] text-muted font-normal ml-2">SKANF Trace</span>
        </h3>
        <div className="flex items-center gap-2">
          {data.vulnerable_called_count > 0 && (
            <span className="text-xs px-2 py-0.5 rounded border font-bold bg-red/20 text-red border-red/40">
              {data.vulnerable_called_count} VULNERABLE
            </span>
          )}
          <span className={`font-mono text-xs px-2 py-0.5 rounded font-bold ${scoreBg(data.risk_score)}`}>
            {data.risk_score}/100
          </span>
        </div>
      </div>

      {/* Summary row */}
      <div className="flex items-center gap-4 mb-4 text-sm">
        <span className="text-muted">
          Transactions: <strong className="text-text">{data.total_transactions}</strong>
        </span>
        <span className="text-muted">
          Callers: <strong className="text-text">{data.unique_callers}</strong>
        </span>
        <span className="text-muted">
          Called functions: <strong className="text-text">{calledSelectors.length}</strong>
        </span>
        <span className="text-muted">
          Uncalled in bytecode: <strong className={data.uncalled_selector_count > 3 ? 'text-yellow' : 'text-text'}>
            {data.uncalled_selector_count}
          </strong>
        </span>
      </div>

      {/* Signals */}
      <div className="space-y-1.5 mb-4">
        {data.signals.map((s, i) => (
          <div key={i} className="flex items-start gap-2 text-xs">
            <span className={`shrink-0 mt-0.5 ${data.risk_score >= 30 ? 'text-red' : 'text-green'}`}>
              {data.risk_score >= 30 ? '\u26A0' : '\u2713'}
            </span>
            <span className="text-text">{s}</span>
          </div>
        ))}
      </div>

      {/* Called selectors table */}
      {calledSelectors.length > 0 && (
        <>
          <p className="text-[10px] text-muted uppercase tracking-wider mb-2">Called Functions (from transaction history)</p>
          <div className="border border-border rounded overflow-hidden mb-4">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-bg text-muted uppercase tracking-wider">
                  <th className="text-left px-3 py-2">Selector</th>
                  <th className="text-left px-3 py-2">Function</th>
                  <th className="text-right px-3 py-2">Calls</th>
                  <th className="text-center px-3 py-2">tx.origin?</th>
                  <th className="text-center px-3 py-2">Risk</th>
                </tr>
              </thead>
              <tbody>
                {calledSelectors.map((ts) => (
                  <tr
                    key={ts.selector}
                    className={`border-t border-border ${ts.tx_origin_nearby ? 'bg-red/5' : 'hover:bg-bg/50'}`}
                  >
                    <td className="px-3 py-2 font-mono text-blue">0x{ts.selector}</td>
                    <td className="px-3 py-2">
                      {ts.name
                        ? <span className="text-text">{ts.name}</span>
                        : <span className="text-muted italic">unknown</span>
                      }
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-text">{ts.call_count}</td>
                    <td className="px-3 py-2 text-center">
                      {ts.tx_origin_nearby
                        ? <span className="text-red font-bold">YES</span>
                        : <span className="text-green">no</span>
                      }
                    </td>
                    <td className="px-3 py-2 text-center">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold ${riskColor(ts.risk_level)}`}>
                        {ts.risk_level.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {/* Uncalled selectors summary */}
      {uncalledSelectors.length > 0 && (
        <div>
          <p className="text-[10px] text-muted uppercase tracking-wider mb-2">
            Uncalled Bytecode Selectors
            <span className="text-yellow ml-1">({uncalledSelectors.length} hidden)</span>
          </p>
          <div className="flex flex-wrap gap-1.5">
            {uncalledSelectors.slice(0, 20).map((ts) => (
              <span
                key={ts.selector}
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                  ts.tx_origin_nearby
                    ? 'border-red/40 bg-red/10 text-red'
                    : 'border-border bg-bg text-muted'
                }`}
              >
                0x{ts.selector}
                {ts.name && <span className="ml-1 text-muted">{ts.name.split('(')[0]}</span>}
                {ts.tx_origin_nearby && <span className="ml-1 text-red">ORIGIN</span>}
              </span>
            ))}
            {uncalledSelectors.length > 20 && (
              <span className="text-[10px] text-muted px-1.5 py-0.5">
                +{uncalledSelectors.length - 20} more
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
