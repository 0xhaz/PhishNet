import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { fetchAttack, analyzeContract } from '@/api/client'
import type { AttackDetail as AttackDetailType } from '@/types'
import KillChainViz from '@/components/attack/KillChainViz'
import TxFlowPanel from '@/components/attack/TxFlowPanel'
import AddressChip from '@/components/shared/AddressChip'
import BytecodeAnalysis from '@/components/contract/BytecodeAnalysis'

interface DetectionResult {
  risk_score: number
  detection_signals: string[]
  contract_type: string
  modules?: { module: string; score: number; signals: string[] }[]
}

export default function AttackDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [attack, setAttack] = useState<AttackDetailType | null>(null)
  const [detection, setDetection] = useState<DetectionResult | null>(null)
  const [detectLoading, setDetectLoading] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!id) return
    fetchAttack(Number(id))
      .then(setAttack)
      .finally(() => setLoading(false))
  }, [id])

  // Run live detection against malicious contract once attack loads
  useEffect(() => {
    if (!attack) return
    const target = attack.malicious_contract || attack.source_contract
    if (!target) return
    setDetectLoading(true)
    analyzeContract(target)
      .then((r) => setDetection(r as DetectionResult))
      .catch(() => null)
      .finally(() => setDetectLoading(false))
  }, [attack])

  if (loading) {
    return (
      <div className="p-6 max-w-5xl mx-auto">
        <div className="h-8 w-48 bg-surface rounded animate-pulse mb-6" />
        <div className="h-40 bg-surface rounded-lg animate-pulse mb-6" />
        <div className="h-64 bg-surface rounded-lg animate-pulse" />
      </div>
    )
  }

  if (!attack) {
    return (
      <div className="p-6 max-w-5xl mx-auto">
        <button onClick={() => navigate('/')} className="text-blue hover:underline text-sm mb-4">&larr; Back</button>
        <p className="text-muted">Attack not found.</p>
      </div>
    )
  }

  const date = attack.timestamp?.slice(0, 19) ?? 'Unknown'
  const typeLabel = attack.attack_type === 'token' ? 'Token-Based Phishing'
    : attack.attack_type === 'pool' ? 'Pool Manipulation'
    : 'Refund Exploit'

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <button onClick={() => navigate('/')} className="text-blue hover:underline text-sm mb-4">&larr; Back to Dashboard</button>

      <div className="mb-6">
        <h2 className="text-xl font-bold">
          Attack #{attack.id} — <span className="text-red">{typeLabel}</span>
        </h2>
        <div className="flex items-center gap-4 mt-2 text-sm text-muted">
          <span>{date}</span>
          <span className="text-red font-bold">{attack.loss_eth?.toFixed(2)} ETH</span>
          <span className="text-yellow">${attack.loss_usd?.toLocaleString()}</span>
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1 mt-2 text-sm">
          <span className="text-muted">Victim: <AddressChip address={attack.victim_bot_address} /></span>
          {attack.malicious_contract && (
            <span className="text-muted">Attacker: <AddressChip address={attack.malicious_contract} /></span>
          )}
          {attack.source_contract && (
            <span className="text-muted">Source Pool: <AddressChip address={attack.source_contract} /></span>
          )}
          {attack.attacker_address && (
            <span className="text-muted">Drain To: <AddressChip address={attack.attacker_address} /></span>
          )}
        </div>
      </div>

      {attack.kill_chain && (
        <>
          <div className="mb-6">
            <KillChainViz killChain={attack.kill_chain} />
          </div>
          <div className="mb-6">
            <TxFlowPanel steps={attack.kill_chain.steps} />
          </div>
        </>
      )}

      <div className="mb-6 bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">Vulnerability Details</h3>
        <div className="text-sm space-y-2">
          {attack.attack_type === 'token' && (
            <>
              <p className="text-text">
                <strong className="text-yellow">Type:</strong> tx.origin authentication bypass
              </p>
              <p className="text-muted">
                The victim bot uses <code className="text-yellow px-1 bg-bg rounded">tx.origin</code> instead of <code className="text-yellow px-1 bg-bg rounded">msg.sender</code> for
                access control. When the bot&apos;s owner (tx.origin) interacts with the malicious token, the token&apos;s callback inherits the
                tx.origin context, allowing it to pass the bot&apos;s auth check and drain funds.
              </p>
            </>
          )}
          {attack.attack_type === 'pool' && (
            <>
              <p className="text-text">
                <strong className="text-yellow">Type:</strong> Malicious pool callback exploitation
              </p>
              <p className="text-muted">
                The attacker created a DEX pool with artificially mispriced assets to lure arbitrage bots. When the victim bot
                swaps through the pool, the pool&apos;s callback function exploits the bot&apos;s tx.origin vulnerability to drain its assets.
              </p>
            </>
          )}
          {attack.attack_type === 'refund' && (
            <>
              <p className="text-text">
                <strong className="text-yellow">Type:</strong> Refund recipient callback exploitation
              </p>
              <p className="text-muted">
                The attacker registered a malicious contract as a refund recipient. When the MEV refund service sends ETH to this
                contract, its receive/fallback function triggers a callback that exploits the bot&apos;s tx.origin vulnerability.
              </p>
            </>
          )}
        </div>
      </div>

      <div className="bg-green-dim border border-green/30 rounded-lg p-5">
        <h3 className="text-sm font-bold text-green uppercase tracking-wider mb-2">PhishNet Early Warning</h3>
        <p className="text-sm text-text mb-3">
          PhishNet monitors new contract deployments in real-time. When the malicious {attack.attack_type === 'pool' ? 'pool' : attack.attack_type === 'refund' ? 'refund contract' : 'token'} was
          deployed <strong className="text-green">(Step 1)</strong>, our detectors would have flagged it <strong className="text-green">~24 seconds</strong> before
          the drain <strong className="text-red">(Step 3)</strong>, giving the bot operator time to revoke approvals or withdraw assets.
        </p>

        {detectLoading && (
          <div className="flex items-center gap-2 text-sm text-muted">
            <span className="inline-block w-3 h-3 border-2 border-green border-t-transparent rounded-full animate-spin" />
            Running detection modules against {attack.malicious_contract ? 'exploit contract' : 'source contract'}...
          </div>
        )}

        {detection && detection.risk_score > 0 && (
          <div className="mt-3 bg-bg/50 border border-green/20 rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs text-muted uppercase tracking-wider">Live Detection Result</span>
              <span className={`font-mono text-xs px-2 py-0.5 rounded font-bold ${
                detection.risk_score >= 70 ? 'bg-red/20 text-red' : detection.risk_score >= 40 ? 'bg-yellow/20 text-yellow' : 'bg-green/20 text-green'
              }`}>
                Risk: {detection.risk_score}/100
              </span>
            </div>

            {detection.modules && detection.modules.length > 0 && (
              <div className="mb-3 flex flex-wrap gap-2">
                {detection.modules.map((m) => (
                  <span key={m.module} className={`text-xs px-2 py-1 rounded border ${
                    m.score >= 70 ? 'border-red/40 text-red bg-red/10' : m.score >= 40 ? 'border-yellow/40 text-yellow bg-yellow/10' : 'border-green/40 text-green bg-green/10'
                  }`}>
                    {m.module.toUpperCase()} Module: {m.score}/100
                  </span>
                ))}
              </div>
            )}

            <div className="space-y-1.5">
              {detection.detection_signals.map((s, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <span className="text-green shrink-0 mt-0.5">&#x2713;</span>
                  <span className="text-text">{s}</span>
                </div>
              ))}
            </div>

            <p className="mt-3 text-xs text-muted border-t border-green/20 pt-2">
              Contract analyzed: <code className="text-green text-[10px]">{(attack.malicious_contract || attack.source_contract)?.slice(0, 18)}...</code>
            </p>
          </div>
        )}

        {detection && detection.risk_score === 0 && !detectLoading && (
          <p className="mt-2 text-xs text-muted">
            Note: The exploit contract may have self-destructed after the attack, making live bytecode analysis unavailable.
          </p>
        )}

        {!detection && !detectLoading && !(attack.malicious_contract || attack.source_contract) && (
          <p className="mt-2 text-xs text-muted">
            No exploit contract address available for live detection analysis.
          </p>
        )}
      </div>

      {/* Bytecode-level analysis of victim bot (SKANF Sections 3.2-3.3) */}
      {attack.victim_bot_address && (
        <div className="mt-6">
          <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">
            Victim Bot Bytecode Analysis
            <span className="text-xs text-muted font-normal ml-2">— {attack.victim_bot_address.slice(0, 10)}...</span>
          </h3>
          <BytecodeAnalysis address={attack.victim_bot_address} />
        </div>
      )}
    </div>
  )
}
