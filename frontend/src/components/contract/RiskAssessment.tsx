import type { VulnerableBot } from '@/types'
import RiskBadge from '@/components/shared/RiskBadge'

interface Props {
  bot: VulnerableBot
}

function riskLevel(bot: VulnerableBot): 'high' | 'med' | 'low' {
  if (bot.attack_count >= 3) return 'high'
  if (bot.attack_count >= 1) return 'med'
  return 'low'
}

function riskScore(bot: VulnerableBot): number {
  let score = 20
  if (bot.attack_count >= 3) score += 40
  else if (bot.attack_count >= 1) score += 20
  if (bot.vulnerability_type === 'both') score += 20
  else if (bot.vulnerability_type) score += 10
  if (bot.is_active) score += 10
  return Math.min(score, 100)
}

export default function RiskAssessment({ bot }: Props) {
  const level = riskLevel(bot)
  const score = riskScore(bot)
  const barColor = level === 'high' ? 'bg-red' : level === 'med' ? 'bg-yellow' : 'bg-green'

  const checks = [
    { label: 'tx.origin vulnerability', active: bot.vulnerability_type === 'tx_origin' || bot.vulnerability_type === 'both' },
    { label: 'Unvalidated call', active: bot.vulnerability_type === 'unvalidated_call' || bot.vulnerability_type === 'both' },
    { label: 'Currently active', active: bot.is_active },
    { label: 'Attack history', active: bot.attack_count > 0 },
  ]

  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider">Risk Assessment</h3>
        <RiskBadge level={level} />
      </div>

      <div className="mb-4">
        <div className="flex justify-between text-xs text-muted mb-1">
          <span>Risk Score</span>
          <span className="font-bold">{score}/100</span>
        </div>
        <div className="h-2 bg-bg rounded-full overflow-hidden">
          <div className={`h-full rounded-full ${barColor} transition-all`} style={{ width: `${score}%` }} />
        </div>
      </div>

      <div className="space-y-2 mb-4">
        {checks.map(c => (
          <div key={c.label} className="flex items-center gap-2 text-sm">
            <span className={c.active ? 'text-red' : 'text-muted'}>{c.active ? '\u2718' : '\u2714'}</span>
            <span className={c.active ? 'text-text' : 'text-muted'}>{c.label}</span>
          </div>
        ))}
      </div>

      <div className="border-t border-border pt-3 text-sm">
        <p className="text-muted">Approx. Balance <span className="text-xs">(historical est.)</span></p>
        <p className="text-green font-bold text-lg">{bot.current_balance_eth?.toFixed(2) ?? '—'} ETH</p>
      </div>
    </div>
  )
}
