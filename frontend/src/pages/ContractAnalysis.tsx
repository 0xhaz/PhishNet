import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { fetchBot, analyzeContract } from '@/api/client'
import type { VulnerableBot } from '@/types'
import AddressChip from '@/components/shared/AddressChip'
import RiskBadge from '@/components/shared/RiskBadge'
import RiskAssessment from '@/components/contract/RiskAssessment'
import AttackHistory from '@/components/contract/AttackHistory'
import RecentInteractions from '@/components/contract/RecentInteractions'
import BytecodeAnalysis from '@/components/contract/BytecodeAnalysis'
import DeployerCluster from '@/components/contract/DeployerCluster'

interface ModuleResult {
  module: string
  score: number
  signals: string[]
}

interface AnalysisResult {
  address: string
  risk_score: number
  detection_signals: string[]
  contract_type: string
  status: string
  targeted_bot: string
  modules?: ModuleResult[]
}

function scoreToLevel(score: number): 'high' | 'med' | 'low' {
  if (score >= 70) return 'high'
  if (score >= 40) return 'med'
  return 'low'
}

export default function ContractAnalysis() {
  const { address } = useParams<{ address: string }>()
  const navigate = useNavigate()
  const [bot, setBot] = useState<VulnerableBot | null>(null)
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!address) return
    Promise.all([
      fetchBot(address).catch(() => null),
      analyzeContract(address).catch(() => null),
    ]).then(([botData, analysisData]) => {
      setBot(botData)
      setAnalysis(analysisData as AnalysisResult | null)
    }).finally(() => setLoading(false))
  }, [address])

  if (loading) {
    return (
      <div className="p-6 max-w-6xl mx-auto">
        <div className="h-8 w-64 bg-surface rounded animate-pulse mb-6" />
        <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-6">
          <div className="h-64 bg-surface rounded-lg animate-pulse" />
          <div className="space-y-6">
            <div className="h-48 bg-surface rounded-lg animate-pulse" />
            <div className="h-48 bg-surface rounded-lg animate-pulse" />
          </div>
        </div>
      </div>
    )
  }

  const typeLabel = analysis?.contract_type === 'mev_bot' ? 'MEV Bot'
    : analysis?.contract_type === 'attacker' ? 'Attacker'
    : analysis?.contract_type === 'token' ? 'Suspicious Token'
    : analysis?.contract_type === 'pool' ? 'Suspicious Pool'
    : analysis?.contract_type === 'refund_recipient' ? 'Refund Recipient'
    : null

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <button onClick={() => navigate('/')} className="text-blue hover:underline text-sm mb-4">&larr; Back to Dashboard</button>

      <div className="mb-6">
        <h2 className="text-xl font-bold flex items-center gap-3">
          Contract Analysis
          {address && <AddressChip address={address} />}
          {typeLabel && <span className="text-xs bg-surface border border-border rounded px-2 py-0.5 text-muted">{typeLabel}</span>}
        </h2>
        {bot && (
          <div className="flex items-center gap-4 mt-2 text-sm text-muted">
            <span>Balance: <strong className="text-green">{bot.current_balance_eth?.toFixed(2) ?? '—'} ETH</strong> <span className="text-xs">(est.)</span></span>
            <span>Status: <strong className={bot.is_active ? 'text-green' : 'text-muted'}>{bot.is_active ? 'Active' : 'Inactive'}</strong></span>
            <span>Attacks: <strong className="text-red">{bot.attack_count}</strong></span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[320px_1fr] gap-6">
        <div className="flex flex-col gap-6">
          {bot ? (
            <RiskAssessment bot={bot} />
          ) : analysis && analysis.risk_score > 0 ? (
            <div className="bg-surface border border-border rounded-lg p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider">Analysis Result</h3>
                <RiskBadge level={scoreToLevel(analysis.risk_score)} />
              </div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-muted text-sm">Risk Score</span>
                <span className="text-text text-sm">{analysis.risk_score}/100</span>
              </div>
              <div className="w-full bg-bg rounded-full h-2 mb-4">
                <div
                  className={`h-2 rounded-full ${analysis.risk_score >= 70 ? 'bg-red' : analysis.risk_score >= 40 ? 'bg-yellow' : 'bg-green'}`}
                  style={{ width: `${analysis.risk_score}%` }}
                />
              </div>
              <div className="space-y-2">
                {analysis.detection_signals.map((s, i) => (
                  <div key={i} className="flex items-start gap-2 text-sm">
                    <span className="text-red shrink-0">&times;</span>
                    <span className="text-text">{s}</span>
                  </div>
                ))}
              </div>
              {analysis.targeted_bot && (
                <div className="mt-4 pt-3 border-t border-border">
                  <p className="text-muted text-xs uppercase mb-1">Targeting Bot</p>
                  <AddressChip address={analysis.targeted_bot} />
                </div>
              )}
              {analysis.modules && analysis.modules.length > 0 && (
                <div className="mt-4 pt-3 border-t border-border">
                  <p className="text-muted text-xs uppercase mb-2">Detection Modules</p>
                  <div className="space-y-2">
                    {analysis.modules.map((m) => (
                      <div key={m.module} className="flex items-center justify-between text-sm">
                        <span className="text-text capitalize">{m.module} Detector</span>
                        <span className={`font-mono text-xs px-2 py-0.5 rounded ${
                          m.score >= 70 ? 'bg-red/20 text-red' : m.score >= 40 ? 'bg-yellow/20 text-yellow' : 'bg-green/20 text-green'
                        }`}>
                          {m.score}/100
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="bg-surface border border-border rounded-lg p-5">
              <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Analysis Result</h3>
              <p className="text-muted text-sm">No records found for this address in PhishNet database.</p>
            </div>
          )}
        </div>
        <div className="flex flex-col gap-6">
          {address && <DeployerCluster address={address} />}
          {address && <BytecodeAnalysis address={address} />}
          {address && <AttackHistory address={address} bot={bot} />}
          {address && <RecentInteractions address={address} />}
        </div>
      </div>
    </div>
  )
}
