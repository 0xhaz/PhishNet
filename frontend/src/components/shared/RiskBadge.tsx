const colors = {
  high: 'bg-red-dim text-red border-red/30',
  med: 'bg-yellow-dim text-yellow border-yellow/30',
  low: 'bg-green-dim text-green border-green/30',
}

interface Props {
  level: 'high' | 'med' | 'low'
  label?: string
}

export default function RiskBadge({ level, label }: Props) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold border ${colors[level]}`}>
      {label ?? level.toUpperCase()}
    </span>
  )
}
