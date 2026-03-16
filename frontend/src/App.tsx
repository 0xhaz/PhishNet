import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Dashboard from '@/pages/Dashboard'
import AttackDetail from '@/pages/AttackDetail'
import ContractAnalysis from '@/pages/ContractAnalysis'
import CostSecurity from '@/pages/CostSecurity'
import AttackerNetwork from '@/pages/AttackerNetwork'
import AttackEvolution from '@/pages/AttackEvolution'
import Header from '@/components/layout/Header'

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-bg text-text font-mono">
        <Header />
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/attack/:id" element={<AttackDetail />} />
          <Route path="/contract/:address" element={<ContractAnalysis />} />
          <Route path="/cost-security" element={<CostSecurity />} />
          <Route path="/network" element={<AttackerNetwork />} />
          <Route path="/evolution" element={<AttackEvolution />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}
