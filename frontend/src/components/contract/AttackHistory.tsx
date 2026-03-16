import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchAttacksByBot } from '@/api/client'
import type { Attack, VulnerableBot } from '@/types'
import AddressChip from '@/components/shared/AddressChip'

interface Props {
  address: string
  bot?: VulnerableBot | null
}

export default function AttackHistory({ address, bot }: Props) {
  const navigate = useNavigate()
  const [attacks, setAttacks] = useState<Attack[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchAttacksByBot(address).then(setAttacks).finally(() => setLoading(false))
  }, [address])

  if (loading) {
    return (
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Attack History</h3>
        {[0, 1, 2].map(i => <div key={i} className="h-8 bg-bg rounded mb-2 animate-pulse" />)}
      </div>
    )
  }

  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Attack History</h3>
      {attacks.length === 0 ? (
        bot && bot.attack_count > 0 ? (
          <div className="text-sm space-y-3 py-2">
            <p className="text-muted">Individual transaction records not available. Summary from on-chain data:</p>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-bg rounded p-3">
                <p className="text-muted text-xs uppercase">Total Attacks</p>
                <p className="text-red font-bold text-lg">{bot.attack_count.toLocaleString()}</p>
              </div>
              <div className="bg-bg rounded p-3">
                <p className="text-muted text-xs uppercase">Total Loss</p>
                <p className="text-red font-bold text-lg">{bot.total_loss_eth?.toFixed(2) ?? '—'} ETH</p>
              </div>
            </div>
          </div>
        ) : (
          <p className="text-muted text-sm text-center py-4">No attacks recorded</p>
        )
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-muted text-xs uppercase border-b border-border">
                <th className="text-left py-2 pr-3">Date</th>
                <th className="text-right py-2 pr-3">Loss (ETH)</th>
                <th className="text-left py-2 pr-3">Pool/Source</th>
                <th className="text-left py-2 pr-3">Attacker</th>
                <th className="text-left py-2 pr-3">Drain To</th>
                <th className="text-left py-2 pr-3">Tx</th>
                <th className="text-left py-2">Detail</th>
              </tr>
            </thead>
            <tbody>
              {attacks.map(a => (
                <tr key={a.id} className="border-b border-border/50">
                  <td className="py-2 pr-3 text-muted text-xs">{a.timestamp?.slice(0, 10)}</td>
                  <td className="py-2 pr-3 text-right text-red font-bold">{a.loss_eth?.toFixed(2)}</td>
                  <td className="py-2 pr-3">
                    <AddressChip address={a.source_contract} />
                  </td>
                  <td className="py-2 pr-3">
                    <AddressChip address={a.malicious_contract} />
                  </td>
                  <td className="py-2 pr-3">
                    <AddressChip address={a.attacker_address} />
                  </td>
                  <td className="py-2 pr-3">
                    <AddressChip address={a.tx_hash} type="tx" />
                  </td>
                  <td className="py-2">
                    <button
                      onClick={() => navigate(`/attack/${a.id}`)}
                      className="text-blue hover:underline text-xs"
                    >
                      Kill Chain &rarr;
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
