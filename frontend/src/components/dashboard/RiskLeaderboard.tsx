import { useNavigate } from 'react-router-dom'
import { useBots } from '@/hooks/useBots'
import AddressChip from '@/components/shared/AddressChip'

interface Props {
  year?: number
}

export default function RiskLeaderboard({ year }: Props) {
  const { bots, loading } = useBots(15, year)
  const navigate = useNavigate()

  if (loading) {
    return (
      <div className="bg-surface border border-border rounded-lg p-4">
        <h3 className="text-sm font-bold text-text-dim mb-3 uppercase tracking-wider">Risk Leaderboard</h3>
        {[0, 1, 2, 3, 4].map(i => (
          <div key={i} className="h-8 bg-bg rounded mb-2 animate-pulse" />
        ))}
      </div>
    )
  }

  return (
    <div className="bg-surface border border-border rounded-lg p-4">
      <h3 className="text-sm font-bold text-text-dim mb-3 uppercase tracking-wider">Risk Leaderboard</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-muted text-xs uppercase border-b border-border">
              <th className="text-left py-2 pr-3">#</th>
              <th className="text-left py-2 pr-3">Bot Address</th>
              <th className="text-right py-2 pr-3">Balance est. (ETH)</th>
              <th className="text-left py-2 pr-3">Vuln Type</th>
              <th className="text-right py-2">Attacks</th>
            </tr>
          </thead>
          <tbody>
            {bots.map((bot, i) => (
              <tr
                key={bot.id}
                className="border-b border-border/50 hover:bg-border/20 cursor-pointer transition-colors"
                onClick={() => navigate(`/contract/${bot.address}`)}
              >
                <td className="py-2 pr-3 text-muted">{i + 1}</td>
                <td className="py-2 pr-3">
                  <AddressChip address={bot.address} link={false} />
                </td>
                <td className="py-2 pr-3 text-right font-mono text-green">
                  {bot.current_balance_eth?.toFixed(2) ?? '—'}
                </td>
                <td className="py-2 pr-3">
                  <span className="text-yellow text-xs">{bot.vulnerability_type ?? '—'}</span>
                </td>
                <td className="py-2 text-right text-red font-bold">{bot.attack_count}</td>
              </tr>
            ))}
            {bots.length === 0 && (
              <tr>
                <td colSpan={5} className="text-center text-muted py-6">No bots found</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
