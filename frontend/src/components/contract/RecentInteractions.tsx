import { useEffect, useState } from 'react'
import { fetchFlaggedByBot } from '@/api/client'
import type { FlaggedContract } from '@/types'
import AddressChip from '@/components/shared/AddressChip'
import RiskBadge from '@/components/shared/RiskBadge'

interface Props {
  address: string
}

function scoreToLevel(score: number): 'high' | 'med' | 'low' {
  if (score >= 70) return 'high'
  if (score >= 40) return 'med'
  return 'low'
}

export default function RecentInteractions({ address }: Props) {
  const [contracts, setContracts] = useState<FlaggedContract[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchFlaggedByBot(address).then(setContracts).finally(() => setLoading(false))
  }, [address])

  if (loading) {
    return (
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Recent Interactions</h3>
        {[0, 1, 2].map(i => <div key={i} className="h-8 bg-bg rounded mb-2 animate-pulse" />)}
      </div>
    )
  }

  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Recent Interactions</h3>
      {contracts.length === 0 ? (
        <p className="text-muted text-sm text-center py-4">No flagged interactions</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-muted text-xs uppercase border-b border-border">
                <th className="text-left py-2 pr-3">Contract</th>
                <th className="text-left py-2 pr-3">Risk</th>
                <th className="text-left py-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {contracts.map(c => (
                <tr key={c.id} className="border-b border-border/50">
                  <td className="py-2 pr-3"><AddressChip address={c.address} /></td>
                  <td className="py-2 pr-3"><RiskBadge level={scoreToLevel(c.risk_score)} label={`${c.risk_score}`} /></td>
                  <td className="py-2 text-xs capitalize text-muted">{c.status?.replace('_', ' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
