import { useEffect, useState } from 'react'
import { fetchStats, fetchTimeline, fetchYears } from '@/api/client'
import type { Stats, TimelineEntry } from '@/types'

export function useStats(year?: number) {
  const [stats, setStats] = useState<Stats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    fetchStats(year).then(setStats).finally(() => setLoading(false))
  }, [year])

  return { stats, loading }
}

export function useTimeline(year?: number) {
  const [data, setData] = useState<TimelineEntry[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    fetchTimeline(year).then(setData).finally(() => setLoading(false))
  }, [year])

  return { data, loading }
}

export function useYears() {
  const [years, setYears] = useState<number[]>([])

  useEffect(() => {
    fetchYears().then(setYears).catch(() => [])
  }, [])

  return years
}
