import { useStats } from '@/hooks/useAttacks'

function fmtETH(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`
  return n.toFixed(1)
}

const cards = [
  { key: 'total_attacks', label: 'Total Drain Events', color: 'text-red', format: (v: number) => v.toLocaleString() },
  { key: 'total_loss_eth', label: 'Total Loss (ETH)', color: 'text-yellow', format: (v: number) => `${fmtETH(v)} ETH` },
  { key: 'bots_at_risk', label: 'Bots at Risk', color: 'text-blue', format: (v: number) => v.toLocaleString() },
  { key: 'flagged_alerts', label: 'Threats Flagged', color: 'text-purple', format: (v: number) => v.toLocaleString() },
] as const

interface Props {
  year?: number
}

export default function StatsPanel({ year }: Props) {
  const { stats, loading } = useStats(year)

  if (loading) {
    return (
      <div className="flex flex-col gap-3">
        {[0, 1, 2, 3, 4].map(i => (
          <div key={i} className="bg-surface border border-border rounded-lg p-4 animate-pulse h-20" />
        ))}
      </div>
    )
  }

  if (!stats) return null

  const detectionPct = Math.round((stats.detection_rate ?? 0) * 100)
  const preventableETH = fmtETH(stats.preventable_loss_eth ?? 0)

  return (
    <div className="flex flex-col gap-3">
      {cards.map(c => (
        <div key={c.key} className="bg-surface border border-border rounded-lg p-4">
          <p className="text-muted text-xs uppercase tracking-wider mb-1">{c.label}</p>
          <p className={`text-2xl font-bold ${c.color}`}>
            {c.format((stats as unknown as Record<string, number>)[c.key] ?? 0)}
          </p>
        </div>
      ))}

      <div className="bg-surface border border-green/30 rounded-lg p-4">
        <p className="text-muted text-xs uppercase tracking-wider mb-1">Detection Rate</p>
        <p className="text-2xl font-bold text-green">{detectionPct}%</p>
        <div className="w-full bg-bg rounded-full h-1.5 mt-2">
          <div className="bg-green h-1.5 rounded-full" style={{ width: `${detectionPct}%` }} />
        </div>
      </div>

      <div className="bg-green-dim border border-green/30 rounded-lg p-4">
        <p className="text-green text-xs uppercase tracking-wider mb-1">Could Have Saved</p>
        <p className="text-2xl font-bold text-green">{preventableETH} ETH</p>
        <p className="text-xs text-muted mt-1">with early detection</p>
      </div>
    </div>
  )
}
