import { useEffect, useState } from 'react'
import { fetchFlagged } from '@/api/client'
import type { FlaggedContract } from '@/types'

export function useFlagged(year?: number) {
  const [contracts, setContracts] = useState<FlaggedContract[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    fetchFlagged(year).then(setContracts).finally(() => setLoading(false))
  }, [year])

  return { contracts, loading }
}
