import axios from 'axios'
import type { Attack, AttackDetail, VulnerableBot, FlaggedContract, Stats, TimelineEntry } from '@/types'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL
    ? `${import.meta.env.VITE_API_URL}/api`
    : '/api',
})

export const fetchAttacks = (page = 1, limit = 50, year?: number) =>
  api.get<Attack[]>('/attacks', { params: { page, limit, ...(year ? { year } : {}) } }).then(r => r.data)

export const fetchAttack = (id: number) =>
  api.get<AttackDetail>(`/attacks/${id}`).then(r => r.data)

export const fetchTimeline = (year?: number) =>
  api.get<TimelineEntry[]>('/attacks/timeline', { params: year ? { year } : {} }).then(r => r.data)

export const fetchYears = () =>
  api.get<number[]>('/attacks/years').then(r => r.data)

export const fetchAttacksByBot = (address: string) =>
  api.get<Attack[]>(`/attacks/by-bot/${address}`).then(r => r.data)

export const fetchBots = (limit = 20, offset = 0, year?: number) =>
  api.get<VulnerableBot[]>('/bots', { params: { limit, offset, ...(year ? { year } : {}) } }).then(r => r.data)

export const fetchBot = (address: string) =>
  api.get<VulnerableBot>(`/bots/${address}`).then(r => r.data)

export const fetchFlagged = (year?: number) =>
  api.get<FlaggedContract[]>('/flagged', { params: year ? { year } : {} }).then(r => r.data)

export const fetchFlaggedByBot = (address: string) =>
  api.get<FlaggedContract[]>(`/flagged/by-bot/${address}`).then(r => r.data)

export const analyzeContract = (address: string) =>
  api.post<FlaggedContract>(`/analyze/${address}`).then(r => r.data)

export interface DeepAnalysis {
  address: string
  bytecode_size: number
  error?: string
  obfuscation: {
    level: string
    score: number
    signals: string[]
    metrics: {
      total_jumps: number
      direct_jumps: number
      indirect_jumps: number
      total_jumpdests: number
      reachable_jumpdests: number
      unreachable_jumpdests: number
      dead_code_bytes: number
      code_density: number
      function_selectors: number
    }
  } | null
  call_analysis: {
    total_calls: number
    vulnerable_count: number
    risk_score: number
    auth_type: string
    signals: string[]
    call_summary: Record<string, number>
    vulnerable_calls: {
      offset: string
      opcode: string
      risk_score: number
      risk_factors: string[]
      has_auth_guard: boolean
    }[]
  } | null
}

export const deepAnalyze = (address: string) =>
  api.post<DeepAnalysis>(`/analyze/${address}/deep`).then(r => r.data)

// ─── Trace-Guided Analysis (SKANF-inspired) ─────────────────────────────────

export interface TracedSelector {
  selector: string
  name: string | null
  call_count: number
  in_bytecode: boolean
  tx_origin_nearby: boolean
  risk_level: string
  sample_txns: string[]
}

export interface TraceAnalysis {
  address: string
  total_transactions: number
  unique_callers: number
  vulnerable_called_count: number
  uncalled_selector_count: number
  risk_score: number
  signals: string[]
  traced_selectors: TracedSelector[]
}

export const traceAnalyze = (address: string) =>
  api.post<TraceAnalysis>(`/analyze/${address}/trace`).then(r => r.data)

export const fetchStats = (year?: number) =>
  api.get<Stats>('/stats', { params: year ? { year } : {} }).then(r => r.data)

// ─── Analytics endpoints ─────────────────────────────────────────────────────

export interface SecurityMethod {
  label: string
  gas_per_call: number
  monthly_gas: number
  monthly_usd: number
  security_level: string
  description: string
}

export interface CostSecurityData {
  methods: Record<string, SecurityMethod>
  real_data: {
    tx_origin_bots: number
    total_bots: number
    tx_origin_pct: number
    total_loss_eth: number
    avg_attacks_per_bot: number
    gas_saved_per_bot_usd: number
    avg_loss_per_bot_eth: number
  }
}

export interface NetworkNode {
  id: string
  type: 'attacker' | 'victim'
  attack_count: number
  victim_count?: number
  total_loss_eth: number
  first_seen?: string
  last_seen?: string
}

export interface NetworkEdge {
  source: string
  target: string
  attack_count: number
  loss_eth: number
}

export interface AttackerNetworkData {
  nodes: NetworkNode[]
  edges: NetworkEdge[]
  shared_victims: { victim_bot_address: string; attacker_count: number }[]
  summary: { total_attackers: number; total_victims: number; total_edges: number }
}

export interface YearData {
  data_year: number
  total_attacks: number
  unique_victims: number
  unique_attackers: number
  total_loss_eth: number
  avg_loss_eth: number
  max_loss_eth: number
  serial_attackers: number
  first_attack: string
  last_attack: string
  top_attacker: { address: string; attacks: number; loss_eth: number } | null
}

export interface EvolutionData {
  years: YearData[]
  monthly: { data_year: number; month: string; count: number; loss_eth: number }[]
}

// ─── Deployer tracking ──────────────────────────────────────────────────────

export interface DeployerInfo {
  deployer: string | null
  deployer_contract_count: number
  related_contracts: {
    address: string
    risk_score: number
    contract_type: string
    status: string
    targeted_bot: string
    detection_signals: string[]
    data_year: number
    deployed_at: string
  }[]
}

export const fetchDeployerInfo = (address: string) =>
  api.get<DeployerInfo>(`/flagged/${address}/deployer`).then(r => r.data)

export const fetchCostSecurity = () =>
  api.get<CostSecurityData>('/analytics/cost-security').then(r => r.data)

export const fetchAttackerNetwork = (minAttacks = 3, limit = 50) =>
  api.get<AttackerNetworkData>('/analytics/attacker-network', { params: { min_attacks: minAttacks, limit } }).then(r => r.data)

export const fetchEvolution = () =>
  api.get<EvolutionData>('/analytics/evolution').then(r => r.data)
