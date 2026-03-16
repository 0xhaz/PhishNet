import { useState } from 'react'
import { useYears } from '@/hooks/useAttacks'
import StatsPanel from '@/components/dashboard/StatsPanel'
import AttackTimeline from '@/components/dashboard/AttackTimeline'
import LiveDetectionFeed from '@/components/dashboard/LiveDetectionFeed'
import RiskLeaderboard from '@/components/dashboard/RiskLeaderboard'

export default function Dashboard() {
  const years = useYears()
  const [selectedYear, setSelectedYear] = useState<number | undefined>(undefined)

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      {/* Year filter */}
      {years.length > 1 && (
        <div className="flex items-center gap-2 mb-4">
          <span className="text-xs text-muted uppercase tracking-wider">Year:</span>
          <button
            onClick={() => setSelectedYear(undefined)}
            className={`text-xs px-2.5 py-1 rounded transition-colors ${
              !selectedYear ? 'bg-blue/20 text-blue border border-blue/40' : 'bg-surface border border-border text-muted hover:text-text'
            }`}
          >
            All
          </button>
          {years.map(y => (
            <button
              key={y}
              onClick={() => setSelectedYear(y)}
              className={`text-xs px-2.5 py-1 rounded transition-colors ${
                selectedYear === y ? 'bg-blue/20 text-blue border border-blue/40' : 'bg-surface border border-border text-muted hover:text-text'
              }`}
            >
              {y}
            </button>
          ))}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-6">
        <div>
          <StatsPanel year={selectedYear} />
        </div>
        <div className="flex flex-col gap-6">
          <AttackTimeline year={selectedYear} />
          <LiveDetectionFeed year={selectedYear} />
          <RiskLeaderboard year={selectedYear} />
        </div>
      </div>
    </div>
  )
}
