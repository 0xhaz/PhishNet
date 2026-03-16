import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { useTimeline } from '@/hooks/useAttacks'

const MONTH_NAMES = ['', 'Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']

function formatMonth(ym: string, showYear: boolean): string {
  const [y, m] = ym.split('-')
  const month = MONTH_NAMES[Number(m)] || m
  return showYear ? `${month} ${y.slice(2)}` : month
}

interface Props {
  year?: number
}

export default function AttackTimeline({ year }: Props) {
  const { data, loading } = useTimeline(year)

  if (loading) {
    return <div className="bg-surface border border-border rounded-lg h-64 animate-pulse" />
  }

  if (data.length === 0) {
    return (
      <div className="bg-surface border border-border rounded-lg h-64 flex items-center justify-center text-muted">
        No timeline data
      </div>
    )
  }

  // Detect if multi-year
  const years = new Set(data.map(d => d.month.slice(0, 4)))
  const multiYear = years.size > 1

  const chartData = data.map(d => ({
    month: d.month,
    attacks: d.count,
    lossEth: d.total_loss_eth,
  }))

  return (
    <div className="bg-surface border border-border rounded-lg p-4">
      <h3 className="text-sm font-bold text-text-dim mb-3 uppercase tracking-wider">
        Attack Timeline
        {year && <span className="text-blue ml-2 font-normal">{year}</span>}
        {!year && multiYear && <span className="text-muted ml-2 font-normal text-[10px]">{[...years].join('-')}</span>}
      </h3>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={chartData}>
          <defs>
            <linearGradient id="redGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="month"
            tick={{ fill: '#6b7280', fontSize: 10 }}
            axisLine={{ stroke: '#1f2433' }}
            tickLine={false}
            tickFormatter={(v: string) => formatMonth(v, multiYear)}
            interval={multiYear ? 2 : 0}
          />
          <YAxis
            tick={{ fill: '#6b7280', fontSize: 11 }}
            axisLine={false}
            tickLine={false}
            width={45}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#141720',
              border: '1px solid #1f2433',
              borderRadius: 8,
              color: '#e5e7eb',
              fontSize: 12,
            }}
            formatter={(value: number, name: string) => {
              if (name === 'attacks') return [value.toLocaleString(), 'Attacks']
              return [`${value.toLocaleString()} ETH`, 'Loss']
            }}
            labelFormatter={(label: string) => {
              const [y, m] = label.split('-')
              return `${MONTH_NAMES[Number(m)] || m} ${y}`
            }}
          />
          <Area
            type="monotone"
            dataKey="attacks"
            stroke="#ef4444"
            strokeWidth={2}
            fill="url(#redGrad)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
