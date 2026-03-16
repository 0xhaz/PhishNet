import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchEvolution } from '@/api/client'
import type { EvolutionData } from '@/api/client'
import { BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import AddressChip from '@/components/shared/AddressChip'

function formatETH(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`
  return n.toFixed(1)
}

function pctChange(curr: number, prev: number): string {
  if (!prev) return 'N/A'
  const pct = ((curr - prev) / prev) * 100
  const sign = pct >= 0 ? '+' : ''
  return `${sign}${pct.toFixed(0)}%`
}

export default function AttackEvolution() {
  const navigate = useNavigate()
  const [data, setData] = useState<EvolutionData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchEvolution()
      .then(setData)
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="p-6 max-w-6xl mx-auto">
        <div className="h-8 w-64 bg-surface rounded animate-pulse mb-6" />
        <div className="h-64 bg-surface rounded-lg animate-pulse mb-6" />
        <div className="h-64 bg-surface rounded-lg animate-pulse" />
      </div>
    )
  }

  if (!data || data.years.length === 0) {
    return (
      <div className="p-6 max-w-6xl mx-auto">
        <button onClick={() => navigate('/')} className="text-blue hover:underline text-sm mb-4">&larr; Back</button>
        <p className="text-muted">No evolution data available. Import multi-year data to see trends.</p>
      </div>
    )
  }

  // Prepare bar chart data
  const yearBars = data.years.map(y => ({
    year: String(y.data_year),
    attacks: y.total_attacks,
    victims: y.unique_victims,
    attackers: y.unique_attackers,
    serial: y.serial_attackers,
  }))

  // Prepare monthly line chart
  const monthlyLine = data.monthly.map(m => ({
    month: m.month,
    count: m.count,
    loss: m.loss_eth,
  }))

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <button onClick={() => navigate('/')} className="text-blue hover:underline text-sm mb-4">&larr; Back to Dashboard</button>

      <h2 className="text-xl font-bold mb-1">Attack Evolution</h2>
      <p className="text-sm text-muted mb-6">How MEV phishing attacks have changed over time</p>

      {/* Data truncation warning */}
      {data.years.length >= 2 && (() => {
        const counts = data.years.map(y => y.total_attacks)
        const maxDiff = Math.max(...counts) - Math.min(...counts)
        const avgCount = counts.reduce((a, b) => a + b, 0) / counts.length
        return maxDiff / avgCount < 0.02 ? (
          <div className="bg-yellow/10 border border-yellow/30 rounded-lg px-4 py-3 mb-6 text-sm">
            <span className="text-yellow font-bold">Note:</span>{' '}
            <span className="text-muted">
              Attack counts are nearly identical across years (~{avgCount.toLocaleString(undefined, {maximumFractionDigits: 0})} each),
              likely due to a row limit in the Dune query. Re-run queries without the LIMIT clause for accurate year-over-year comparison.
            </span>
          </div>
        ) : null
      })()}

      {/* Year-over-year comparison cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        {data.years.map((y, i) => {
          const prev = i > 0 ? data.years[i - 1] : null
          return (
            <div key={y.data_year} className="bg-surface border border-border rounded-lg p-4">
              <h3 className="text-lg font-bold text-text mb-2">{y.data_year}</h3>
              <div className="space-y-1.5 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted">Attacks</span>
                  <span>
                    <strong className="text-text">{y.total_attacks.toLocaleString()}</strong>
                    {prev && <span className={`text-xs ml-1 ${y.total_attacks > prev.total_attacks ? 'text-red' : 'text-green'}`}>
                      {pctChange(y.total_attacks, prev.total_attacks)}
                    </span>}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted">Unique Victims</span>
                  <span>
                    <strong className="text-text">{y.unique_victims.toLocaleString()}</strong>
                    {prev && <span className={`text-xs ml-1 ${y.unique_victims > prev.unique_victims ? 'text-red' : 'text-green'}`}>
                      {pctChange(y.unique_victims, prev.unique_victims)}
                    </span>}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted">Total Loss</span>
                  <span className="text-yellow font-bold">{formatETH(y.total_loss_eth)} ETH</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted">Avg Loss/Attack</span>
                  <span className="text-text">{y.avg_loss_eth.toFixed(2)} ETH</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted">Max Single Loss</span>
                  <span className="text-red">{formatETH(y.max_loss_eth)} ETH</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted">Serial Attackers</span>
                  <span>
                    <strong className="text-text">{y.serial_attackers}</strong>
                    <span className="text-[10px] text-muted ml-1">(5+ attacks)</span>
                  </span>
                </div>
              </div>
              {y.top_attacker && (
                <div className="mt-3 pt-2 border-t border-border">
                  <p className="text-[10px] text-muted uppercase mb-1">Top Attacker</p>
                  <div className="flex items-center justify-between">
                    <AddressChip address={y.top_attacker.address} />
                    <span className="text-xs text-red">{y.top_attacker.attacks} attacks</span>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Year-over-year bar chart */}
      <div className="bg-surface border border-border rounded-lg p-5 mb-6">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-4">Annual Comparison</h3>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={yearBars} barCategoryGap="25%">
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis dataKey="year" stroke="#64748b" fontSize={12} />
            <YAxis stroke="#64748b" fontSize={11} />
            <Tooltip
              contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
              itemStyle={{ color: '#e2e8f0' }}
            />
            <Legend iconSize={10} wrapperStyle={{ fontSize: 11 }} />
            <Bar dataKey="attacks" name="Total Attacks" fill="#ef4444" radius={[4, 4, 0, 0]} />
            <Bar dataKey="victims" name="Unique Victims" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            <Bar dataKey="serial" name="Serial Attackers" fill="#eab308" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Monthly trend line */}
      <div className="bg-surface border border-border rounded-lg p-5">
        <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-4">Monthly Attack Volume</h3>
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={monthlyLine}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis
              dataKey="month"
              stroke="#64748b"
              fontSize={10}
              tickFormatter={(v: string) => {
                const [y, m] = v.split('-')
                return `${m}/${y.slice(2)}`
              }}
            />
            <YAxis stroke="#64748b" fontSize={11} />
            <Tooltip
              contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
              labelFormatter={(v: string) => {
                const [y, m] = v.split('-')
                const months = ['', 'Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
                return `${months[Number(m)]} ${y}`
              }}
              formatter={(value: number, name: string) => [
                name === 'count' ? value.toLocaleString() : `${formatETH(value)} ETH`,
                name === 'count' ? 'Attacks' : 'Loss'
              ]}
            />
            <Line type="monotone" dataKey="count" name="count" stroke="#ef4444" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
