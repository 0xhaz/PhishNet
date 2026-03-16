import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchDeployerInfo } from '@/api/client'
import type { DeployerInfo } from '@/api/client'
import AddressChip from '@/components/shared/AddressChip'
import RiskBadge from '@/components/shared/RiskBadge'

function scoreToLevel(score: number): 'high' | 'med' | 'low' {
  if (score >= 70) return 'high'
  if (score >= 40) return 'med'
  return 'low'
}

interface Props {
  address: string
}

export default function DeployerCluster({ address }: Props) {
  const [data, setData] = useState<DeployerInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    setLoading(true)
    fetchDeployerInfo(address)
      .then(setData)
      .catch(() => null)
      .finally(() => setLoading(false))
  }, [address])

  if (loading) {
    return (
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Deployer Analysis</h3>
        <div className="flex items-center gap-2 text-sm text-muted">
          <span className="inline-block w-3 h-3 border-2 border-blue border-t-transparent rounded-full animate-spin" />
          Looking up contract deployer...
        </div>
      </div>
    )
  }

  if (!data || !data.deployer) {
    return (
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Deployer Analysis</h3>
        <p className="text-muted text-sm">
          Could not determine the deployer for this contract.
          {' '}Re-importing data from Dune will populate deployer information.
        </p>
      </div>
    )
  }

  const isSerial = data.deployer_contract_count >= 3
  const relatedCount = data.related_contracts.length

  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider">
          Deployer Analysis
        </h3>
        {isSerial && (
          <span className="text-xs px-2 py-0.5 rounded border font-bold bg-red/20 text-red border-red/40">
            SERIAL DEPLOYER
          </span>
        )}
      </div>

      {/* Deployer address */}
      <div className="flex items-center justify-between mb-3">
        <span className="text-muted text-xs uppercase">Deployed by</span>
        <AddressChip address={data.deployer} />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        <div className="bg-bg rounded p-2">
          <p className="text-[10px] text-muted uppercase">Flagged Contracts</p>
          <p className={`text-lg font-bold font-mono ${isSerial ? 'text-red' : 'text-text'}`}>
            {relatedCount + 1}
          </p>
        </div>
        <div className="bg-bg rounded p-2">
          <p className="text-[10px] text-muted uppercase">Total from Deployer</p>
          <p className={`text-lg font-bold font-mono ${data.deployer_contract_count >= 10 ? 'text-red' : data.deployer_contract_count >= 3 ? 'text-yellow' : 'text-green'}`}>
            {data.deployer_contract_count > 0 ? data.deployer_contract_count : '—'}
          </p>
        </div>
      </div>

      {/* Related contracts */}
      {relatedCount > 0 && (
        <>
          <p className="text-xs text-muted uppercase tracking-wider mb-2">
            Other Flagged Contracts by Same Deployer ({relatedCount})
          </p>
          <div className="space-y-1.5 max-h-56 overflow-y-auto">
            {data.related_contracts.map(c => (
              <div
                key={c.address}
                className="flex items-center justify-between px-3 py-2 rounded bg-bg hover:bg-border/30 cursor-pointer transition-colors"
                onClick={() => navigate(`/contract/${c.address}`)}
              >
                <div className="flex items-center gap-2">
                  <RiskBadge level={scoreToLevel(c.risk_score)} />
                  <AddressChip address={c.address} link={false} />
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted text-[10px]">{c.data_year}</span>
                  <span className="font-mono text-xs text-muted">{c.risk_score}/100</span>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {relatedCount === 0 && !isSerial && (
        <p className="text-muted text-xs">
          No other flagged contracts found from this deployer in the PhishNet database.
        </p>
      )}

      {relatedCount === 0 && isSerial && (
        <p className="text-yellow text-xs">
          This deployer has created {data.deployer_contract_count} contracts on-chain,
          but only this one appears in our flagged database so far.
        </p>
      )}
    </div>
  )
}
