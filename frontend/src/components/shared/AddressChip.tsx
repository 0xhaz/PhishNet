interface Props {
  address: string
  link?: boolean
  type?: 'address' | 'tx'
}

export default function AddressChip({ address, link = true, type = 'address' }: Props) {
  if (!address) return <span className="text-muted text-sm">N/A</span>
  const short = `${address.slice(0, 6)}...${address.slice(-4)}`
  if (link) {
    return (
      <a
        href={`https://etherscan.io/${type}/${address}`}
        target="_blank"
        rel="noreferrer"
        className="text-blue hover:underline font-mono text-sm"
      >
        {short}
      </a>
    )
  }
  return <span className="text-blue font-mono text-sm">{short}</span>
}
