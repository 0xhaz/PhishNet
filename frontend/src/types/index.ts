export type AttackType = 'token' | 'pool' | 'refund'
export type RiskLevel = 'high' | 'med' | 'low'
export type FlaggedStatus = 'alert' | 'watching' | 'clear' | 'confirmed_attack'
export type VulnType = 'tx_origin' | 'unvalidated_call' | 'both'
export type ObfuscationLevel = 'none' | 'low' | 'high'

export interface Attack {
  id: number
  tx_hash: string
  block_number: number
  timestamp: string
  attack_type: AttackType
  attacker_address: string
  victim_bot_address: string
  malicious_contract: string
  source_contract: string
  loss_eth: number
  loss_usd: number
  previously_known: boolean
}

export interface KillChainStep {
  step: number
  action: 'deploy' | 'lure' | 'drain'
  tx: string
  block: number
  contract?: string
  target?: string
  amount?: string
  internal_calls?: { from: string; to: string; selector: string; value: string }[]
}

export interface KillChain {
  steps: KillChainStep[]
  total_loss: string
  detection_window: string
}

export interface AttackDetail extends Attack {
  kill_chain: KillChain
}

export interface VulnerableBot {
  id: number
  address: string
  first_seen: string
  vulnerability_type: VulnType
  total_loss_eth: number
  current_balance_eth: number
  attack_count: number
  is_active: boolean
  obfuscation_level: ObfuscationLevel
}

export interface FlaggedContract {
  id: number
  address: string
  deployed_at: string
  contract_type: 'token' | 'pool' | 'refund_recipient'
  risk_score: number
  detection_signals: string[]
  targeted_bot: string
  status: FlaggedStatus
}

export interface TimelineEntry {
  month: string
  attack_type: string
  count: number
  total_loss_eth: number
  total_loss_usd: number
}

export interface Stats {
  total_attacks: number
  total_loss_usd: number
  total_loss_eth: number
  bots_at_risk: number
  preventable_loss_usd: number
  preventable_loss_eth: number
  detection_rate: number
  flagged_alerts: number
  by_type: {
    token: { detected: number; total: number }
    pool: { detected: number; total: number }
    refund: { detected: number; total: number }
  }
}
