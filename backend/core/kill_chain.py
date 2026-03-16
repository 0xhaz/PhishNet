"""Reconstruct the kill chain for a known attack from on-chain data."""
from __future__ import annotations
from dataclasses import dataclass, field
from database import get_db
from core.data_fetcher import EthDataFetcher

fetcher = EthDataFetcher()


@dataclass
class KillChainStep:
    step: int
    action: str  # 'deploy' | 'lure' | 'drain'
    tx: str
    block: int
    contract: str | None = None
    target: str | None = None
    amount: str | None = None
    internal_calls: list[dict] = field(default_factory=list)


@dataclass
class KillChain:
    steps: list[KillChainStep]
    total_loss: str
    detection_window: str  # e.g. "3 seconds"


class KillChainParser:
    def reconstruct(self, attack_id: int) -> KillChain:
        with get_db() as db:
            row = db.execute(
                "SELECT * FROM attacks WHERE id = ?", (attack_id,)
            ).fetchone()
        if not row:
            raise ValueError(f"Attack {attack_id} not found")

        attack = dict(row)
        steps: list[KillChainStep] = []

        # Step 1 — deployment of malicious contract
        creation = fetcher.get_contract_creation_tx(attack["malicious_contract"])
        steps.append(KillChainStep(
            step=1,
            action="deploy",
            tx=creation.get("txHash", ""),
            block=int(creation.get("blockNumber", 0)),
            contract=attack["malicious_contract"],
        ))

        # Step 2 — lure / token transfer to victim
        transfers = fetcher.get_token_transfers(attack["malicious_contract"])
        lure = next(
            (t for t in transfers if t["to"].lower() == attack["victim_bot_address"].lower()),
            None,
        )
        if lure:
            steps.append(KillChainStep(
                step=2,
                action="lure",
                tx=lure["hash"],
                block=int(lure["blockNumber"]),
                target=attack["victim_bot_address"],
            ))

        # Step 3 — drain transaction
        internal = fetcher.get_internal_transactions(attack["tx_hash"])
        steps.append(KillChainStep(
            step=3,
            action="drain",
            tx=attack["tx_hash"],
            block=attack["block_number"],
            amount=f"{attack['loss_eth']:.2f} ETH",
            internal_calls=internal[:10],  # top 10 internal calls
        ))

        deploy_block = steps[0].block
        drain_block = steps[-1].block
        block_delta = drain_block - deploy_block
        detection_window = f"{block_delta} blocks (~{block_delta * 12}s)"

        return KillChain(
            steps=steps,
            total_loss=f"{attack['loss_eth']:.2f} ETH (${attack['loss_usd']:,.0f})",
            detection_window=detection_window,
        )
