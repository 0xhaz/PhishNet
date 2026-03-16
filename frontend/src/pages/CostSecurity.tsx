import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchCostSecurity } from '@/api/client'
import type { CostSecurityData } from '@/api/client'

const METHOD_ORDER = ['tx_origin', 'msg_sender', 'ecrecover', 'create2_verify'] as const
const LEVEL_COLORS: Record<string, string> = {
  vulnerable: 'text-red bg-red/20 border-red/40',
  moderate: 'text-yellow bg-yellow/20 border-yellow/40',
  strong: 'text-green bg-green/20 border-green/40',
  maximum: 'text-blue bg-blue/20 border-blue/40',
}
const BAR_COLORS: Record<string, string> = {
  vulnerable: 'bg-red',
  moderate: 'bg-yellow',
  strong: 'bg-green',
  maximum: 'bg-blue',
}

function formatGas(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`
  if (n >= 1e6) return `${(n / 1e6).toFixed(0)}M`
  if (n >= 1e3) return `${(n / 1e3).toFixed(0)}K`
  return String(n)
}

function formatUSD(n: number): string {
  if (n >= 1000) return `$${(n / 1000).toFixed(1)}K`
  if (n >= 1) return `$${n.toFixed(2)}`
  return `$${n.toFixed(2)}`
}

export default function CostSecurity() {
  const navigate = useNavigate()
  const [data, setData] = useState<CostSecurityData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchCostSecurity()
      .then(setData)
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="p-6 max-w-5xl mx-auto">
        <div className="h-8 w-64 bg-surface rounded animate-pulse mb-6" />
        <div className="h-96 bg-surface rounded-lg animate-pulse" />
      </div>
    )
  }

  if (!data) return null

  const { methods, real_data } = data
  const maxGas = Math.max(...METHOD_ORDER.map(k => methods[k]?.monthly_gas ?? 0))

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <button onClick={() => navigate('/')} className="text-blue hover:underline text-sm mb-4">&larr; Back to Dashboard</button>

      <h2 className="text-xl font-bold mb-1">Cost vs Security Tradeoff</h2>
      <p className="text-sm text-muted mb-6">SKANF Paper Section 7.1 — Why MEV bots choose vulnerable authentication</p>

      {/* Key insight callout */}
      <div className="bg-red/10 border border-red/30 rounded-lg p-4 mb-6">
        <p className="text-sm text-text">
          <strong className="text-red">{real_data.tx_origin_pct}%</strong> of analyzed MEV bots use <code className="text-red bg-bg px-1 rounded">tx.origin</code> for access control.
          Switching to <code className="text-green bg-bg px-1 rounded">msg.sender</code> costs <strong className="text-green">{formatUSD(real_data.gas_saved_per_bot_usd)}/month extra</strong> but
          would have prevented <strong className="text-yellow">{real_data.avg_loss_per_bot_eth.toLocaleString()} ETH</strong> average loss per bot.
        </p>
      </div>

      {/* Comparison table */}
      <div className="bg-surface border border-border rounded-lg overflow-hidden mb-6">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-bg text-muted uppercase tracking-wider text-xs">
              <th className="text-left px-4 py-3">Method</th>
              <th className="text-left px-4 py-3">Security</th>
              <th className="text-right px-4 py-3">Gas/Call</th>
              <th className="text-right px-4 py-3">Monthly Gas</th>
              <th className="text-right px-4 py-3">Monthly Cost</th>
              <th className="text-left px-4 py-3 w-1/4">Relative Cost</th>
            </tr>
          </thead>
          <tbody>
            {METHOD_ORDER.map(key => {
              const m = methods[key]
              if (!m) return null
              const ratio = m.monthly_gas / maxGas
              return (
                <tr key={key} className="border-t border-border hover:bg-bg/50">
                  <td className="px-4 py-3">
                    <span className="font-bold text-text">{m.label}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded border font-bold ${LEVEL_COLORS[m.security_level] || ''}`}>
                      {m.security_level.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right font-mono">{m.gas_per_call.toLocaleString()}</td>
                  <td className="px-4 py-3 text-right font-mono">{formatGas(m.monthly_gas)}</td>
                  <td className="px-4 py-3 text-right font-mono">{formatUSD(m.monthly_usd)}</td>
                  <td className="px-4 py-3">
                    <div className="w-full bg-bg rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${BAR_COLORS[m.security_level] || 'bg-muted'}`}
                        style={{ width: `${Math.max(ratio * 100, 2)}%` }}
                      />
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Method descriptions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        {METHOD_ORDER.map(key => {
          const m = methods[key]
          if (!m) return null
          return (
            <div key={key} className={`border rounded-lg p-4 ${key === 'tx_origin' ? 'border-red/40 bg-red/5' : 'border-border bg-surface'}`}>
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-bold text-sm">{m.label}</h4>
                <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold ${LEVEL_COLORS[m.security_level] || ''}`}>
                  {m.security_level}
                </span>
              </div>
              <p className="text-xs text-muted">{m.description}</p>
            </div>
          )
        })}
      </div>

      {/* Real data summary */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-4">Real-World Impact (from PhishNet data)</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-bg rounded-lg p-3">
            <p className="text-[10px] text-muted uppercase">Vulnerable Bots</p>
            <p className="text-lg font-bold text-red">{real_data.tx_origin_bots.toLocaleString()}</p>
            <p className="text-[10px] text-muted">of {real_data.total_bots.toLocaleString()} total</p>
          </div>
          <div className="bg-bg rounded-lg p-3">
            <p className="text-[10px] text-muted uppercase">Total Losses</p>
            <p className="text-lg font-bold text-yellow">{(real_data.total_loss_eth / 1000).toFixed(0)}K ETH</p>
            <p className="text-[10px] text-muted">from tx.origin exploits</p>
          </div>
          <div className="bg-bg rounded-lg p-3">
            <p className="text-[10px] text-muted uppercase">Avg Attacks/Bot</p>
            <p className="text-lg font-bold text-text">{real_data.avg_attacks_per_bot}</p>
            <p className="text-[10px] text-muted">repeated targeting</p>
          </div>
          <div className="bg-bg rounded-lg p-3">
            <p className="text-[10px] text-muted uppercase">Fix Cost</p>
            <p className="text-lg font-bold text-green">{formatUSD(0.30)}/mo</p>
            <p className="text-[10px] text-muted">msg.sender upgrade</p>
          </div>
        </div>
      </div>
    </div>
  )
}
