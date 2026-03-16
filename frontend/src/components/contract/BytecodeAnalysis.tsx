import { useEffect, useState } from 'react'
import { deepAnalyze } from '@/api/client'
import type { DeepAnalysis } from '@/api/client'

interface Props {
  address: string
}

function scoreColor(score: number) {
  if (score >= 60) return 'text-red'
  if (score >= 30) return 'text-yellow'
  return 'text-green'
}

function scoreBg(score: number) {
  if (score >= 60) return 'bg-red/20 text-red'
  if (score >= 30) return 'bg-yellow/20 text-yellow'
  return 'bg-green/20 text-green'
}

function levelColor(level: string) {
  switch (level) {
    case 'heavy': return 'bg-red/20 text-red border-red/40'
    case 'moderate': return 'bg-yellow/20 text-yellow border-yellow/40'
    case 'light': return 'bg-blue/20 text-blue border-blue/40'
    default: return 'bg-green/20 text-green border-green/40'
  }
}

function authColor(type: string) {
  switch (type) {
    case 'tx.origin': return 'bg-red/20 text-red'
    case 'none': return 'bg-red/20 text-red'
    case 'msg.sender': return 'bg-green/20 text-green'
    case 'both': return 'bg-yellow/20 text-yellow'
    default: return 'bg-surface text-muted'
  }
}

export default function BytecodeAnalysis({ address }: Props) {
  const [data, setData] = useState<DeepAnalysis | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    deepAnalyze(address)
      .then(setData)
      .catch(() => null)
      .finally(() => setLoading(false))
  }, [address])

  if (loading) {
    return (
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Bytecode Analysis</h3>
        <div className="flex items-center gap-2 text-sm text-muted">
          <span className="inline-block w-3 h-3 border-2 border-blue border-t-transparent rounded-full animate-spin" />
          Fetching bytecode and running SKANF analysis...
        </div>
      </div>
    )
  }

  if (!data || data.error) {
    return (
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">
          Bytecode Analysis
          <span className="text-[10px] text-muted font-normal ml-2">SKANF &sect;3.2-3.3</span>
        </h3>
        <p className="text-muted text-sm mb-2">No deployed bytecode found on-chain.</p>
        <p className="text-muted text-xs">
          This typically means the contract <strong className="text-yellow">self-destructed</strong> after
          executing the attack (a common anti-forensics technique), or the address is an EOA (wallet).
          PhishNet flagged this contract based on its on-chain behavior before destruction.
        </p>
      </div>
    )
  }

  const obf = data.obfuscation
  const calls = data.call_analysis

  return (
    <div className="space-y-4">
      {/* Obfuscation Analysis — Section 3.2 */}
      {obf && (
        <div className="bg-surface border border-border rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider">
              Obfuscation Analysis
              <span className="text-[10px] text-muted font-normal ml-2">SKANF &sect;3.2</span>
            </h3>
            <div className="flex items-center gap-2">
              <span className={`text-xs px-2 py-0.5 rounded border font-bold ${levelColor(obf.level)}`}>
                {obf.level.toUpperCase()}
              </span>
              <span className={`font-mono text-xs px-2 py-0.5 rounded font-bold ${scoreBg(obf.score)}`}>
                {obf.score}/100
              </span>
            </div>
          </div>

          {/* Metrics grid */}
          <div className="grid grid-cols-3 gap-3 mb-4">
            <div className="bg-bg rounded p-2">
              <p className="text-[10px] text-muted uppercase">Jumps</p>
              <p className="text-sm font-mono">
                <span className="text-green">{obf.metrics.direct_jumps}</span>
                <span className="text-muted"> direct / </span>
                <span className={obf.metrics.indirect_jumps > 0 ? 'text-red' : 'text-green'}>{obf.metrics.indirect_jumps}</span>
                <span className="text-muted"> indirect</span>
              </p>
            </div>
            <div className="bg-bg rounded p-2">
              <p className="text-[10px] text-muted uppercase">JUMPDESTs</p>
              <p className="text-sm font-mono">
                <span className="text-green">{obf.metrics.reachable_jumpdests}</span>
                <span className="text-muted"> reachable / </span>
                <span className={obf.metrics.unreachable_jumpdests > 0 ? 'text-yellow' : 'text-green'}>{obf.metrics.unreachable_jumpdests}</span>
                <span className="text-muted"> dead</span>
              </p>
            </div>
            <div className="bg-bg rounded p-2">
              <p className="text-[10px] text-muted uppercase">Code Density</p>
              <p className="text-sm font-mono">
                <span className={obf.metrics.code_density < 0.3 ? 'text-yellow' : 'text-green'}>
                  {(obf.metrics.code_density * 100).toFixed(1)}%
                </span>
                <span className="text-muted text-xs ml-1">({data.bytecode_size} bytes)</span>
              </p>
            </div>
          </div>

          {/* Dead code bar */}
          {obf.metrics.dead_code_bytes > 0 && (
            <div className="mb-4">
              <div className="flex items-center justify-between text-[10px] text-muted mb-1">
                <span>Dead Code</span>
                <span>{obf.metrics.dead_code_bytes} / {data.bytecode_size} bytes</span>
              </div>
              <div className="w-full bg-bg rounded-full h-1.5">
                <div
                  className="h-1.5 rounded-full bg-yellow/60"
                  style={{ width: `${Math.min((obf.metrics.dead_code_bytes / data.bytecode_size) * 100, 100)}%` }}
                />
              </div>
            </div>
          )}

          {/* Signals */}
          <div className="space-y-1.5">
            {obf.signals.map((s, i) => (
              <div key={i} className="flex items-start gap-2 text-xs">
                <span className={`shrink-0 mt-0.5 ${obf.score >= 30 ? 'text-yellow' : 'text-green'}`}>
                  {obf.score >= 30 ? '\u26A0' : '\u2713'}
                </span>
                <span className="text-text">{s}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Vulnerable CALL Analysis — Section 3.3 */}
      {calls && (
        <div className="bg-surface border border-border rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider">
              Vulnerable CALL Finder
              <span className="text-[10px] text-muted font-normal ml-2">SKANF &sect;3.3</span>
            </h3>
            <div className="flex items-center gap-2">
              <span className={`text-xs px-2 py-0.5 rounded font-bold ${authColor(calls.auth_type)}`}>
                Auth: {calls.auth_type === 'none' ? 'NONE' : calls.auth_type}
              </span>
              <span className={`font-mono text-xs px-2 py-0.5 rounded font-bold ${scoreBg(calls.risk_score)}`}>
                {calls.risk_score}/100
              </span>
            </div>
          </div>

          {/* Summary row */}
          <div className="flex items-center gap-4 mb-4 text-sm">
            <span className="text-muted">
              Total calls: <strong className="text-text">{calls.total_calls}</strong>
            </span>
            <span className="text-muted">
              Vulnerable: <strong className={calls.vulnerable_count > 0 ? 'text-red' : 'text-green'}>{calls.vulnerable_count}</strong>
            </span>
            {Object.entries(calls.call_summary).map(([op, count]) => (
              <span key={op} className="text-xs bg-bg rounded px-2 py-0.5 font-mono text-muted">
                {op}: {count}
              </span>
            ))}
          </div>

          {/* Signals */}
          <div className="space-y-1.5 mb-4">
            {calls.signals.map((s, i) => (
              <div key={i} className="flex items-start gap-2 text-xs">
                <span className={`shrink-0 mt-0.5 ${calls.risk_score >= 30 ? 'text-red' : 'text-green'}`}>
                  {calls.risk_score >= 30 ? '\u26A0' : '\u2713'}
                </span>
                <span className="text-text">{s}</span>
              </div>
            ))}
          </div>

          {/* Vulnerable calls table */}
          {calls.vulnerable_calls.length > 0 && (
            <div className="border border-border rounded overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-bg text-muted uppercase tracking-wider">
                    <th className="text-left px-3 py-2">Offset</th>
                    <th className="text-left px-3 py-2">Opcode</th>
                    <th className="text-left px-3 py-2">Risk</th>
                    <th className="text-left px-3 py-2">Factors</th>
                  </tr>
                </thead>
                <tbody>
                  {calls.vulnerable_calls.map((vc, i) => (
                    <tr key={i} className="border-t border-border hover:bg-bg/50">
                      <td className="px-3 py-2 font-mono text-blue">{vc.offset}</td>
                      <td className="px-3 py-2 font-mono">
                        <span className={
                          vc.opcode === 'DELEGATECALL' ? 'text-red' :
                          vc.opcode === 'CALLCODE' ? 'text-red' :
                          'text-text'
                        }>{vc.opcode}</span>
                      </td>
                      <td className="px-3 py-2">
                        <span className={`font-mono font-bold ${scoreColor(vc.risk_score)}`}>{vc.risk_score}</span>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {vc.risk_factors.map((f, j) => (
                            <span key={j} className="bg-bg text-muted rounded px-1.5 py-0.5 text-[10px]">{f}</span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
