import { useNavigate } from 'react-router-dom'
import { useFlagged } from '@/hooks/useFlagged'
import RiskBadge from '@/components/shared/RiskBadge'
import AddressChip from '@/components/shared/AddressChip'

function scoreToLevel(score: number): 'high' | 'med' | 'low' {
  if (score >= 70) return 'high'
  if (score >= 40) return 'med'
  return 'low'
}

interface Props {
  year?: number
}

export default function LiveDetectionFeed({ year }: Props) {
  const { contracts, loading } = useFlagged(year)
  const navigate = useNavigate()

  if (loading) {
    return (
      <div className="bg-surface border border-border rounded-lg p-4">
        <h3 className="text-sm font-bold text-text-dim mb-3 uppercase tracking-wider">Live Detection Feed</h3>
        {[0, 1, 2, 3, 4].map(i => (
          <div key={i} className="h-10 bg-bg rounded mb-2 animate-pulse" />
        ))}
      </div>
    )
  }

  const top = contracts.slice(0, 10)

  return (
    <div className="bg-surface border border-border rounded-lg p-4">
      <h3 className="text-sm font-bold text-text-dim mb-3 uppercase tracking-wider">Live Detection Feed</h3>
      <div className="space-y-2 max-h-80 overflow-y-auto">
        {top.map(c => (
          <div
            key={c.id}
            className="flex items-center justify-between px-3 py-2 rounded bg-bg hover:bg-border/30 cursor-pointer transition-colors"
            onClick={() => navigate(`/contract/${c.address}`)}
          >
            <div className="flex items-center gap-3">
              <RiskBadge level={scoreToLevel(c.risk_score)} />
              <AddressChip address={c.address} />
            </div>
            <span className="text-muted text-xs truncate max-w-[180px]">
              {Array.isArray(c.detection_signals) && c.detection_signals.length > 0
                ? c.detection_signals[0]
                : 'Flagged'}
            </span>
          </div>
        ))}
        {top.length === 0 && <p className="text-muted text-sm text-center py-4">No flagged contracts</p>}
      </div>
    </div>
  )
}
