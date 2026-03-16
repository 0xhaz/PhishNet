import { useEffect, useState } from 'react'
import { fetchBots } from '@/api/client'
import type { VulnerableBot } from '@/types'

export function useBots(limit = 20, year?: number) {
  const [bots, setBots] = useState<VulnerableBot[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    fetchBots(limit, 0, year).then(setBots).finally(() => setLoading(false))
  }, [limit, year])

  return { bots, loading }
}
