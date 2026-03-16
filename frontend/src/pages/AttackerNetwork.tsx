import { useEffect, useState, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchAttackerNetwork } from '@/api/client'
import type { AttackerNetworkData, NetworkNode } from '@/api/client'
import * as d3 from 'd3'

interface SimNode extends NetworkNode, d3.SimulationNodeDatum {}
interface SimEdge extends d3.SimulationLinkDatum<SimNode> {
  attack_count: number
  loss_eth: number
}

export default function AttackerNetwork() {
  const navigate = useNavigate()
  const [data, setData] = useState<AttackerNetworkData | null>(null)
  const [loading, setLoading] = useState(true)
  const [minAttacks, setMinAttacks] = useState(10)
  const svgRef = useRef<SVGSVGElement>(null)
  const tooltipRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setLoading(true)
    fetchAttackerNetwork(minAttacks, 40)
      .then(setData)
      .finally(() => setLoading(false))
  }, [minAttacks])

  const renderGraph = useCallback(() => {
    if (!data || !svgRef.current) return

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const width = svgRef.current.clientWidth || 900
    const height = 500

    svg.attr('viewBox', `0 0 ${width} ${height}`)

    // Prepare data
    const nodes: SimNode[] = data.nodes.map(n => ({ ...n }))
    const nodeMap = new Map(nodes.map(n => [n.id, n]))
    const edges: SimEdge[] = data.edges
      .filter(e => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map(e => ({ ...e, source: e.source, target: e.target }))

    if (nodes.length === 0) return

    // Scale for node sizes
    const maxLoss = Math.max(...nodes.map(n => n.total_loss_eth || 1))
    const rScale = d3.scaleSqrt().domain([0, maxLoss]).range([3, 18])

    // Force simulation
    const simulation = d3.forceSimulation<SimNode>(nodes)
      .force('link', d3.forceLink<SimNode, SimEdge>(edges).id(d => d.id).distance(60).strength(0.3))
      .force('charge', d3.forceManyBody().strength(-120))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide<SimNode>().radius(d => rScale(d.total_loss_eth || 0) + 2))

    // Container with zoom
    const g = svg.append('g')
    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.3, 4])
        .on('zoom', (event) => g.attr('transform', event.transform)) as any
    )

    // Edges
    const link = g.append('g')
      .selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke', '#334155')
      .attr('stroke-width', (d: SimEdge) => Math.max(0.5, Math.min(d.attack_count / 5, 3)))
      .attr('stroke-opacity', 0.4)

    // Nodes
    const node = g.append('g')
      .selectAll('circle')
      .data(nodes)
      .join('circle')
      .attr('r', (d: SimNode) => rScale(d.total_loss_eth || 0))
      .attr('fill', (d: SimNode) => d.type === 'attacker' ? '#ef4444' : '#3b82f6')
      .attr('stroke', (d: SimNode) => d.type === 'attacker' ? '#fca5a5' : '#93c5fd')
      .attr('stroke-width', 1)
      .attr('cursor', 'pointer')
      .on('click', (_: MouseEvent, d: SimNode) => {
        navigate(`/contract/${d.id}`)
      })
      .on('mouseover', function(event: MouseEvent, d: SimNode) {
        d3.select(this).attr('stroke-width', 3)
        if (tooltipRef.current) {
          const tt = tooltipRef.current
          tt.style.display = 'block'
          tt.style.left = `${event.offsetX + 12}px`
          tt.style.top = `${event.offsetY - 10}px`
          tt.innerHTML = `
            <div class="text-[10px] text-muted uppercase">${d.type}</div>
            <div class="font-mono text-xs text-text">${d.id.slice(0, 10)}...${d.id.slice(-6)}</div>
            <div class="text-xs text-muted mt-1">
              Attacks: <strong class="${d.type === 'attacker' ? 'text-red' : 'text-blue'}">${d.attack_count}</strong>
              ${d.victim_count ? ` | Victims: <strong class="text-red">${d.victim_count}</strong>` : ''}
            </div>
            <div class="text-xs text-yellow">${(d.total_loss_eth || 0).toLocaleString()} ETH</div>
          `
        }
      })
      .on('mouseout', function() {
        d3.select(this).attr('stroke-width', 1)
        if (tooltipRef.current) tooltipRef.current.style.display = 'none'
      })
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .call(d3.drag<any, SimNode>()
        .on('start', (event: any, d: SimNode) => {
          if (!event.active) simulation.alphaTarget(0.3).restart()
          d.fx = d.x
          d.fy = d.y
        })
        .on('drag', (event: any, d: SimNode) => {
          d.fx = event.x
          d.fy = event.y
        })
        .on('end', (event: any, d: SimNode) => {
          if (!event.active) simulation.alphaTarget(0)
          d.fx = null
          d.fy = null
        })
      )

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y)

      node
        .attr('cx', (d: SimNode) => d.x ?? 0)
        .attr('cy', (d: SimNode) => d.y ?? 0)
    })

    return () => simulation.stop()
  }, [data, navigate])

  useEffect(() => {
    renderGraph()
  }, [renderGraph])

  if (loading) {
    return (
      <div className="p-6 max-w-6xl mx-auto">
        <div className="h-8 w-64 bg-surface rounded animate-pulse mb-6" />
        <div className="h-[500px] bg-surface rounded-lg animate-pulse" />
      </div>
    )
  }

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <button onClick={() => navigate('/')} className="text-blue hover:underline text-sm mb-4">&larr; Back to Dashboard</button>

      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold">Attacker Network Graph</h2>
          <p className="text-sm text-muted">Serial deployers and their victim clusters</p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <label className="text-muted">Min attacks:</label>
          <select
            value={minAttacks}
            onChange={(e) => setMinAttacks(Number(e.target.value))}
            className="bg-bg border border-border rounded px-2 py-1 text-text text-sm"
          >
            <option value={3}>3+</option>
            <option value={5}>5+</option>
            <option value={10}>10+</option>
            <option value={25}>25+</option>
            <option value={50}>50+</option>
          </select>
        </div>
      </div>

      {/* Summary stats */}
      {data && (
        <div className="flex gap-4 mb-4">
          <div className="bg-surface border border-border rounded px-3 py-2 text-sm">
            <span className="text-muted">Attackers: </span>
            <strong className="text-red">{data.summary.total_attackers}</strong>
          </div>
          <div className="bg-surface border border-border rounded px-3 py-2 text-sm">
            <span className="text-muted">Victims: </span>
            <strong className="text-blue">{data.summary.total_victims}</strong>
          </div>
          <div className="bg-surface border border-border rounded px-3 py-2 text-sm">
            <span className="text-muted">Connections: </span>
            <strong className="text-text">{data.summary.total_edges}</strong>
          </div>
          <div className="flex items-center gap-3 ml-auto text-xs text-muted">
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red inline-block" /> Attacker</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-blue inline-block" /> Victim Bot</span>
          </div>
        </div>
      )}

      {/* Graph */}
      <div className="relative bg-surface border border-border rounded-lg overflow-hidden">
        <svg ref={svgRef} className="w-full" style={{ height: 500 }} />
        <div
          ref={tooltipRef}
          className="absolute hidden bg-bg border border-border rounded-lg px-3 py-2 pointer-events-none shadow-lg z-10"
          style={{ display: 'none' }}
        />
      </div>

      {/* Shared victims (bots attacked by multiple attackers) */}
      {data && data.shared_victims.length > 0 && (
        <div className="mt-6 bg-surface border border-border rounded-lg p-5">
          <h3 className="text-sm font-bold text-text-dim uppercase tracking-wider mb-3">
            Shared Victims (attacked by multiple deployers)
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {data.shared_victims.slice(0, 12).map((sv) => (
              <button
                key={sv.victim_bot_address}
                onClick={() => navigate(`/contract/${sv.victim_bot_address}`)}
                className="flex items-center justify-between bg-bg rounded px-3 py-2 text-sm hover:bg-bg/80 transition-colors text-left"
              >
                <span className="font-mono text-xs text-blue truncate">
                  {sv.victim_bot_address.slice(0, 10)}...{sv.victim_bot_address.slice(-6)}
                </span>
                <span className="text-xs text-red font-bold ml-2 shrink-0">
                  {sv.attacker_count} attackers
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
