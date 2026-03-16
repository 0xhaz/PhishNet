import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'

const NAV_LINKS = [
  { path: '/', label: 'Dashboard' },
  { path: '/evolution', label: 'Evolution' },
  { path: '/network', label: 'Network' },
  { path: '/cost-security', label: 'Cost vs Security' },
]

export default function Header() {
  const [query, setQuery] = useState('')
  const navigate = useNavigate()
  const location = useLocation()

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const addr = query.trim()
    if (addr) {
      navigate(`/contract/${addr}`)
      setQuery('')
    }
  }

  return (
    <header className="h-14 bg-surface border-b border-border flex items-center justify-between px-6 shrink-0">
      <div className="flex items-center gap-3">
        <span className="text-red text-xl">&#x1F3A3;</span>
        <h1 className="text-lg font-bold tracking-wide cursor-pointer" onClick={() => navigate('/')}>
          PhishNet
        </h1>
        <span className="text-text-dim text-sm hidden md:inline">MEV Phishing Monitor</span>
        <nav className="hidden sm:flex items-center gap-1 ml-4">
          {NAV_LINKS.map(link => (
            <button
              key={link.path}
              onClick={() => navigate(link.path)}
              className={`text-xs px-2 py-1 rounded transition-colors ${
                location.pathname === link.path
                  ? 'bg-bg text-text border border-border'
                  : 'text-muted hover:text-text'
              }`}
            >
              {link.label}
            </button>
          ))}
        </nav>
      </div>
      <form onSubmit={handleSubmit}>
        <input
          className="bg-bg border border-border rounded px-3 py-1 text-sm w-64 placeholder:text-muted focus:border-blue focus:outline-none"
          placeholder="Analyze contract: 0x..."
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
      </form>
    </header>
  )
}
