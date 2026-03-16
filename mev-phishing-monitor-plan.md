# MEV Phishing Monitor — Hackathon Build Plan

## Project: PhishNet — Real-Time MEV Phishing Detection Dashboard

**Track:** DeFi, Security & Mechanism Design (SKANF)
**Paper:** "Insecurity Through Obscurity: Veiled Vulnerabilities in Closed-Source Contracts"
**Mentor:** Sen Yang, PhD Student, Yale University

---

## Executive Summary

PhishNet is a monitoring dashboard that detects and visualizes MEV phishing attacks — a class of exploit where attackers deploy malicious tokens, pools, or refund contracts to steal assets from vulnerable MEV bots. The SKANF paper uncovered 104 such attacks totaling $2.76M in losses, with only 3 previously known. PhishNet operationalizes these findings into a live product.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND (React)                      │
│  ┌──────────┐ ┌──────────────┐ ┌─────────────────────┐  │
│  │ Live Feed│ │Attack Timeline│ │  Risk Leaderboard   │  │
│  │ (flagged │ │  (historical │ │  (vulnerable bots    │  │
│  │contracts)│ │   104 attacks│ │   ranked by assets)  │  │
│  └────┬─────┘ └──────┬───────┘ └──────────┬──────────┘  │
│       │              │                     │             │
│  ┌────┴──────────────┴─────────────────────┴──────────┐  │
│  │              Attack Detail View                     │  │
│  │  (kill chain visualization, tx flow, loss amount)   │  │
│  └─────────────────────┬───────────────────────────────┘  │
└────────────────────────┼─────────────────────────────────┘
                         │ REST API
┌────────────────────────┼─────────────────────────────────┐
│                  BACKEND (Python)                         │
│  ┌─────────────────────┴───────────────────────────────┐  │
│  │               API Server (FastAPI)                   │  │
│  └──────┬──────────────┬───────────────────┬───────────┘  │
│         │              │                   │              │
│  ┌──────┴─────┐ ┌──────┴──────┐ ┌──────────┴──────────┐  │
│  │  Token     │ │  Pool       │ │  Refund             │  │
│  │  Detector  │ │  Detector   │ │  Detector           │  │
│  │  (Module 1)│ │  (Module 2) │ │  (Module 3)         │  │
│  └──────┬─────┘ └──────┬──────┘ └──────────┬──────────┘  │
│         │              │                   │              │
│  ┌──────┴──────────────┴───────────────────┴──────────┐  │
│  │           Data Layer (SQLite + Cache)               │  │
│  └──────────────────────┬─────────────────────────────┘  │
└─────────────────────────┼────────────────────────────────┘
                          │
┌─────────────────────────┼────────────────────────────────┐
│              DATA SOURCES                                 │
│  ┌──────────┐ ┌─────────┴──┐ ┌────────────────────────┐  │
│  │Ethereum  │ │ Etherscan  │ │ SKANF Paper Dataset    │  │
│  │Archive   │ │ API        │ │ (104 attacks, 37       │  │
│  │Node      │ │            │ │  victims, tx hashes)   │  │
│  └──────────┘ └────────────┘ └────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer       | Technology                | Why                                              |
|-------------|---------------------------|--------------------------------------------------|
| Frontend    | React + TypeScript        | Component-based, fast iteration                  |
| Charts      | Recharts + D3             | Timeline viz, flow diagrams                      |
| Styling     | Tailwind CSS              | Rapid UI, dark theme for security-tool aesthetic  |
| Backend     | Python + FastAPI          | Best EVM analysis libraries (web3.py, pyevmasm)  |
| Database    | SQLite                    | Zero config, single file, enough for hackathon   |
| EVM Data    | Alchemy / QuickNode       | Archive node access for historical txs           |
| Contract    | Etherscan API             | Bytecode retrieval, ABI lookup, tx history       |

---

## Data Foundation: Dune Analytics (Primary Source)

The SKANF paper's raw dataset is not publicly available for direct extraction. Instead, we use **Dune Analytics** as the primary data source, querying on-chain data year-by-year to discover and reconstruct MEV phishing attacks.

### Strategy: Year-Based Dataset Collection

Queries are executed per-year starting from **2021**, allowing:
- Smaller query scopes (lower Dune credit cost)
- Incremental dataset building (validate pipeline with 2021, then expand)
- Idempotent re-runs (each year's data can be refreshed independently)

### Data Pipeline

```
1. scrape_bot_addresses.py   → data/seed/known_mev_bots.json (3271 addresses)
2. inject_bot_addresses.py   → patch Dune SQL with top 500 bot addresses
3. run_dune_queries.py       → execute 4 Dune queries per year → SQLite
4. seed_db.py                → init schema + optional Etherscan enrichment
```

### Year Execution

```bash
# Start with 2021
python scripts/run_dune_queries.py --year 2021

# Then expand year by year
python scripts/run_dune_queries.py --year 2022
python scripts/run_dune_queries.py --year 2023

# Or run all years at once
python scripts/run_dune_queries.py --all-years
```

### Dune Queries (4 total)

| Query | Purpose | Output Table |
|-------|---------|-------------|
| 01_token_phishing_candidates | Fresh tokens sent to known MEV bots | flagged_contracts |
| 02_drain_transactions | ETH/WETH drains from known bots | attacks |
| 03_attack_timeline | Monthly aggregated attack stats | (computed on the fly) |
| 04_vulnerable_bots_ranked | Bots ranked by ETH balance at risk | vulnerable_bots |

### Reference: SKANF Paper Findings

The paper reported 104 attacks ($2.76M losses) across 37 victims (July 2021 - April 2025).
Our Dune queries independently discover these and potentially additional attacks from on-chain data.

| Metric | Paper | Our Target |
|--------|-------|------------|
| Attack types | Token (101), Pool (3), Refund (1) | Token + Pool (via Dune) |
| Victims | 37 unique bots | Discovered from 500 known bot addresses |
| Date range | Jul 2021 — Apr 2025 | 2021 — present (year by year) |

---

## Detection Engine: Three Modules

### Module 1 — Token-Based Phishing Detector

**What it catches:** 101 of 104 known attacks

**Attack pattern:**
1. Attacker deploys a malicious ERC-20 token
2. The token's `transfer()` or callback functions contain crafted calldata
3. Attacker sends/swaps this token to trigger interaction with a vulnerable MEV bot
4. When the bot processes the token (via tx.origin context), the crafted calldata causes the bot to transfer its real assets to the attacker

**Detection signals (ranked by reliability):**

| Signal                          | Weight | How to detect                                    |
|---------------------------------|--------|--------------------------------------------------|
| New token with external CALLs   | High   | Disassemble bytecode, find CALL opcodes in token functions that target addresses not in the token contract |
| Calldata matches transfer/approve signatures | High | Check if embedded calldata starts with `0xa9059cbb` (transfer) or `0x095ea7b3` (approve) |
| Token sent to known MEV bot     | High   | Cross-reference recipient against known MEV bot addresses from SKANF dataset |
| Token deployed by address with attack history | Med | Check deployer's history for previous malicious tokens |
| Token has no liquidity/market   | Med    | No DEX pairs, no transfers except to targets     |
| Unusual bytecode patterns       | Low    | Token bytecode contains encoded addresses of high-value contracts |

**Implementation:**

```python
# Pseudocode for Token Detector
class TokenPhishingDetector:
    def analyze_contract(self, address: str) -> RiskReport:
        bytecode = get_bytecode(address)
        
        # 1. Check if it's an ERC-20 (has transfer/balanceOf selectors)
        if not has_erc20_interface(bytecode):
            return RiskReport(risk=0)
        
        # 2. Disassemble and find CALL instructions
        calls = extract_external_calls(bytecode)
        
        # 3. Check if any CALL targets or calldata reference
        #    known function selectors (transfer, approve, transferFrom)
        suspicious_calls = []
        for call in calls:
            if call.selector in DANGEROUS_SELECTORS:
                suspicious_calls.append(call)
        
        # 4. Check if token has been sent to known MEV bots
        transfers = get_token_transfers(address)
        targeted_bots = [t for t in transfers 
                        if t.to in KNOWN_MEV_BOTS]
        
        # 5. Score and return
        risk_score = compute_risk(suspicious_calls, targeted_bots)
        return RiskReport(
            risk=risk_score,
            attack_type="token-based",
            suspicious_calls=suspicious_calls,
            targeted_bots=targeted_bots
        )
```

### Module 2 — Pool-Based Phishing Detector

**What it catches:** 3 of 104 known attacks

**Attack pattern:**
1. Attacker creates a malicious DEX pool (Uniswap-style)
2. Pool contains an artificially mispriced pair to lure arbitrage bots
3. When a searcher swaps through the pool, the pool's callback exploits tx.origin
4. The bot's assets drain during the swap execution

**Detection signals:**

| Signal                              | Weight | How to detect                                  |
|-------------------------------------|--------|------------------------------------------------|
| New pool with freshly deployed token| High   | Pool created where one token is < 24hrs old    |
| Artificial price discrepancy        | High   | Pool price deviates >50% from market price on major DEXs |
| Pool contract has unusual callbacks | Med    | Bytecode analysis of the pool factory output   |
| Low liquidity designed as bait      | Med    | Just enough liquidity to trigger bot thresholds|
| Token in pool has no other markets  | Med    | Only exists in this one pool                   |

**Implementation:**

```python
class PoolPhishingDetector:
    def analyze_pool(self, pool_address: str) -> RiskReport:
        # 1. Get pool tokens
        token0, token1 = get_pool_tokens(pool_address)
        
        # 2. Check token ages
        token0_age = get_contract_age(token0)
        token1_age = get_contract_age(token1)
        
        # 3. Check if either token is suspicious
        if token0_age < timedelta(hours=24):
            token_report = token_detector.analyze(token0)
        
        # 4. Check price discrepancy against other markets
        pool_price = get_pool_price(pool_address)
        market_price = get_market_price(token0, token1)
        price_deviation = abs(pool_price - market_price) / market_price
        
        # 5. Check liquidity (bait-level amounts)
        liquidity = get_pool_liquidity(pool_address)
        
        return RiskReport(
            risk=compute_pool_risk(token0_age, price_deviation, liquidity),
            attack_type="pool-based"
        )
```

### Module 3 — Refund-Based Phishing Detector

**What it catches:** Novel attack pattern discovered by SKANF paper

**Attack pattern (most sophisticated):**
1. Attacker deploys a contract and registers it as a refund recipient with an MEV refund service (e.g., BackRunMe)
2. Attacker creates a legitimate-looking MEV opportunity using compliant tokens
3. MEV bot captures the opportunity, generating a refund
4. Refund service sends ETH to attacker's contract
5. Attacker's contract's `receive()`/`fallback()` function triggers a callback that exploits the bot's tx.origin vulnerability

**Detection signals:**

| Signal                                  | Weight | How to detect                                |
|-----------------------------------------|--------|----------------------------------------------|
| New contract registered as refund addr  | High   | Monitor refund service registrations         |
| Contract has non-trivial fallback/receive| High  | Bytecode contains logic in fallback function |
| Fallback makes external calls           | High   | CALL opcodes in fallback code path           |
| Contract deployed by known attacker     | Med    | Cross-reference deployer history             |
| Refund triggers chain of internal txs   | Med    | Trace refund transactions for deep call chains|

**Implementation:**

```python
class RefundPhishingDetector:
    def analyze_refund_contract(self, address: str) -> RiskReport:
        bytecode = get_bytecode(address)
        
        # 1. Check if contract has a non-empty fallback/receive
        has_fallback = check_fallback_function(bytecode)
        
        # 2. If fallback exists, check for external CALLs
        if has_fallback:
            fallback_calls = extract_fallback_calls(bytecode)
            suspicious = [c for c in fallback_calls 
                         if c.selector in DANGEROUS_SELECTORS]
        
        # 3. Check if address is registered with known refund services
        is_refund_recipient = check_refund_registrations(address)
        
        return RiskReport(
            risk=compute_refund_risk(has_fallback, suspicious, is_refund_recipient),
            attack_type="refund-based"
        )
```

---

## Frontend: Dashboard Layout

### Screen 1 — Main Dashboard

```
┌──────────────────────────────────────────────────────────────────┐
│  🐟 PhishNet — MEV Phishing Monitor                    [Search] │
├──────────┬───────────────────────────────────────────────────────┤
│          │                                                       │
│ STATS    │  ATTACK TIMELINE                                      │
│          │  ┌───────────────────────────────────────────────────┐ │
│ Total    │  │  ●          ●    ●●  ●       ●●●    ●  ●●●●     │ │
│ Attacks  │  │     ●   ●          ●    ●        ●●       ●  ●  │ │
│  104     │  │  ●    ●   ●●   ●    ●●    ●          ●       ●  │ │
│          │  │──┼────┼────┼────┼────┼────┼────┼────┼────┼────┼──│ │
│ Total    │  │ Jul  Jan  Jul  Jan  Jul  Jan  Jul  Jan  Jul  Apr │ │
│ Losses   │  │ 2021 2022 2022 2023 2023 2024 2024 2025 2025     │ │
│ $2.76M   │  └───────────────────────────────────────────────────┘ │
│          │  ● Token-based (101)  ● Pool-based (3)  ● Refund (1) │
│ Bots at  │                                                       │
│ Risk     │  LIVE DETECTION FEED                                  │
│  37      │  ┌───────────────────────────────────────────────────┐ │
│          │  │ 🔴 HIGH  0x3a1f..  Token deployed targeting       │ │
│ Could    │  │          bot 0x8c2e.. | Risk: 92/100 | 2min ago  │ │
│ Have     │  │                                                   │ │
│ Saved    │  │ 🟡 MED   0xb7d2..  New pool with fresh token     │ │
│ $2.45M   │  │          Price deviation: 340% | 8min ago         │ │
│          │  │                                                   │ │
│          │  │ 🟢 LOW   0xf1a9..  Refund contract with          │ │
│          │  │          non-trivial fallback | 15min ago          │ │
│          │  └───────────────────────────────────────────────────┘ │
│          │                                                       │
│          │  RISK LEADERBOARD — Most Vulnerable Active Bots       │
│          │  ┌────┬──────────┬──────────┬───────────┬───────────┐ │
│          │  │Rank│ Bot Addr │ Assets   │ Vuln Type │ Targeted? │ │
│          │  ├────┼──────────┼──────────┼───────────┼───────────┤ │
│          │  │ 1  │ 0x8c2e.. │ 142 ETH  │ tx.origin │ Yes (3x)  │ │
│          │  │ 2  │ 0xf4b1.. │ 89 ETH   │ CALL ctrl │ Yes (1x)  │ │
│          │  │ 3  │ 0xa3d7.. │ 51 ETH   │ tx.origin │ No        │ │
│          │  └────┴──────────┴──────────┴───────────┴───────────┘ │
└──────────┴───────────────────────────────────────────────────────┘
```

### Screen 2 — Attack Detail View (click on any attack)

```
┌──────────────────────────────────────────────────────────────────┐
│  ← Back    Attack #47 — Token-Based Phishing                    │
│            March 15, 2024  |  Loss: 250 ETH ($636,000)          │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  KILL CHAIN VISUALIZATION                                        │
│                                                                  │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐            │
│  │ Attacker │───>│ Deploy       │───>│ Send Token   │            │
│  │ 0xdead.. │    │ Malicious    │    │ to Victim    │            │
│  └──────────┘    │ Token        │    │ Bot 0x8c2e.. │            │
│                  │ 0x3a1f..     │    └──────┬───────┘            │
│                  └──────────────┘           │                    │
│                                             ▼                    │
│  ┌──────────────┐    ┌──────────────────────────────┐            │
│  │ Assets Drain │<───│ Bot processes token           │            │
│  │ 250 ETH to   │    │ tx.origin == bot owner        │            │
│  │ attacker     │    │ Crafted calldata triggers     │            │
│  └──────────────┘    │ unauthorized transfer         │            │
│                      └──────────────────────────────┘            │
│                                                                  │
│  TRANSACTION FLOW                                                │
│  ┌───────────────────────────────────────────────────────────┐   │
│  │ Step 1: Token Deploy    tx: 0xabc123..    Block: 19234567 │   │
│  │ Step 2: Token Transfer  tx: 0xdef456..    Block: 19234570 │   │
│  │ Step 3: Asset Drain     tx: 0x789abc..    Block: 19234570 │   │
│  │         Internal: CALL to WETH.transfer(attacker, 250e18) │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                  │
│  VULNERABILITY DETAILS                                           │
│  Type: tx.origin authentication bypass                           │
│  The victim bot uses tx.origin instead of msg.sender for         │
│  access control. When the bot's owner (tx.origin) interacts     │
│  with the malicious token, the token's callback inherits the     │
│  tx.origin context, allowing it to pass the bot's auth check.   │
│                                                                  │
│  DETECTION: PhishNet would have flagged the malicious token      │
│  at deployment (Step 1), 3 seconds before the drain (Step 3).   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Screen 3 — Contract Analysis View (click on any bot or flagged contract)

```
┌──────────────────────────────────────────────────────────────────┐
│  ← Back    Contract Analysis: 0x8c2e4f...                        │
│            MEV Bot  |  Active since Jan 2023  |  Balance: 142 ETH│
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  RISK ASSESSMENT                                                 │
│  ┌────────────────────────────────────────┐                      │
│  │  Overall Risk: ██████████░░ 85/100     │                      │
│  │                                         │                      │
│  │  tx.origin usage:      DETECTED  🔴    │                      │
│  │  Unvalidated CALLs:    DETECTED  🔴    │                      │
│  │  Obfuscation level:    HIGH      🟡    │                      │
│  │  Previous attacks:     3 incidents 🔴   │                      │
│  │  Current token balance: 142 ETH  🔴    │                      │
│  └────────────────────────────────────────┘                      │
│                                                                  │
│  ATTACK HISTORY                                                  │
│  ┌──────────┬────────────┬────────┬──────────────────┐           │
│  │ Date     │ Type       │ Loss   │ Tx Hash          │           │
│  ├──────────┼────────────┼────────┼──────────────────┤           │
│  │ Mar 2024 │ Token      │ 250 ETH│ 0x789abc..       │           │
│  │ Nov 2023 │ Token      │ 45 ETH │ 0x456def..       │           │
│  │ Aug 2023 │ Pool       │ 12 ETH │ 0x123abc..       │           │
│  └──────────┴────────────┴────────┴──────────────────┘           │
│                                                                  │
│  RECENT INTERACTIONS (potential incoming attacks)                 │
│  ┌──────────┬──────────────┬────────────┬──────────────┐         │
│  │ Time     │ Token/Pool   │ Risk Score │ Status       │         │
│  ├──────────┼──────────────┼────────────┼──────────────┤         │
│  │ 2min ago │ 0x3a1f..     │ 92/100     │ 🔴 ALERT    │         │
│  │ 1hr ago  │ 0xb7d2..     │ 45/100     │ 🟡 WATCHING │         │
│  │ 3hr ago  │ 0xf1a9..     │ 12/100     │ 🟢 CLEAR    │         │
│  └──────────┴──────────────┴────────────┴──────────────┘         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Day-by-Day Build Plan

Assuming a 3-day hackathon format. Adjust if longer.

### Pre-Hackathon (Before Day 1)

**Goal: Data pipeline setup and initial dataset collection**

- [x] Read SKANF paper thoroughly, especially Section RQ3 (real-world attacks)
- [x] Set up development environment: Python 3.11+, Node.js 18+, React project with Tailwind
- [x] Get API keys: Alchemy (archive node), Etherscan (contract data), Dune Analytics
- [x] Scrape MEV bot addresses: `python scripts/scrape_bot_addresses.py`
- [x] Inject bot addresses into Dune SQL: `python scripts/inject_bot_addresses.py --limit 500`
- [ ] Create Dune queries in UI (free plan): paste each SQL file, save, cache IDs with `--set-id`
- [ ] Run initial dataset: `python scripts/run_dune_queries.py --year 2021`
- [ ] Enrich via Etherscan: `python scripts/seed_db.py --enrich`
- [ ] Validate: check SQLite for attack records, flagged contracts, vulnerable bots
- [x] Scaffold the React app with routing: Dashboard, Attack Detail, Contract Analysis
- [x] Set up FastAPI backend with basic health endpoint

**Database schema** (see `backend/database.py`): attacks, vulnerable_bots, flagged_contracts tables with `data_year` tracking for year-based dataset management.

---

### Day 1: Historical Data Layer + Core Backend

**Morning (4 hours): Backend data pipeline**

- [ ] Build the Ethereum data fetcher module:

```python
# data_fetcher.py
class EthDataFetcher:
    def get_contract_bytecode(self, address: str) -> bytes
    def get_contract_creation_tx(self, address: str) -> dict
    def get_token_transfers(self, address: str) -> list
    def get_internal_transactions(self, tx_hash: str) -> list
    def get_erc20_balances(self, address: str) -> dict
    def get_transaction_trace(self, tx_hash: str) -> dict
```

- [ ] Build the attack reconstructor — for each known attack in the database, fetch and store:
  - The malicious contract's bytecode
  - The attack transaction's internal call trace
  - The token transfer events (ERC-20 Transfer logs)
  - The timeline: deployment tx → interaction tx → drain tx

- [ ] Build the kill chain parser:

```python
# kill_chain.py
class KillChainParser:
    def reconstruct(self, attack_id: int) -> KillChain:
        """
        Returns a structured kill chain:
        {
            steps: [
                {step: 1, action: "deploy", tx: "0x...", block: 123, contract: "0x.."},
                {step: 2, action: "lure", tx: "0x...", block: 125, target: "0x.."},
                {step: 3, action: "drain", tx: "0x...", block: 125, amount: "250 ETH",
                 internal_calls: [{from, to, selector, value}]}
            ],
            total_loss: "250 ETH",
            detection_window: "3 seconds"  -- time between step 1 and step 3
        }
        """
```

**Afternoon (4 hours): Token-based detector (Module 1)**

This is the highest-value detector (covers 101/104 attacks).

- [ ] Build bytecode analyzer:

```python
# bytecode_analyzer.py
class BytecodeAnalyzer:
    DANGEROUS_SELECTORS = {
        "a9059cbb": "transfer(address,uint256)",
        "095ea7b3": "approve(address,uint256)",
        "23b872dd": "transferFrom(address,address,uint256)",
    }
    
    def extract_external_calls(self, bytecode: bytes) -> list:
        """Find all CALL/DELEGATECALL/STATICCALL instructions
        and attempt to determine target and selector"""
    
    def check_tx_origin_usage(self, bytecode: bytes) -> bool:
        """Check if bytecode contains ORIGIN opcode (0x32)"""
    
    def has_erc20_interface(self, bytecode: bytes) -> bool:
        """Check for transfer/balanceOf/totalSupply selectors"""
    
    def get_embedded_addresses(self, bytecode: bytes) -> list:
        """Extract 20-byte sequences that look like addresses"""
```

- [ ] Wire up the token detector with the fetcher and analyzer
- [ ] **Validation checkpoint:** Run the detector against the 37 known victim contracts and the malicious tokens from the dataset. Track detection rate. Target: flag at least 70% of known malicious tokens.

**Evening (2 hours): FastAPI endpoints**

- [ ] Build API endpoints:

```
GET  /api/attacks                    -- list all known attacks (paginated)
GET  /api/attacks/{id}               -- single attack with kill chain
GET  /api/attacks/timeline           -- aggregated for timeline chart
GET  /api/bots                       -- vulnerable bots ranked by risk
GET  /api/bots/{address}             -- single bot with history
GET  /api/flagged                    -- currently flagged contracts
POST /api/analyze/{address}          -- on-demand analysis of a contract
GET  /api/stats                      -- summary statistics
```

---

### Day 2: Frontend Build

**Morning (4 hours): Main dashboard**

- [ ] Build the stats sidebar (Total Attacks, Total Losses, Bots at Risk, "Could Have Saved" figure)
- [ ] Build the attack timeline using Recharts:
  - X-axis: time (July 2021 — April 2025)
  - Y-axis: loss amount
  - Dot size: proportional to ETH lost
  - Dot color: attack type (token=red, pool=blue, refund=purple)
  - Hover: show attack summary tooltip
  - Click: navigate to Attack Detail view
- [ ] Build the live detection feed component (for now, populated from known attacks with simulated timestamps)
- [ ] Build the risk leaderboard table

**Afternoon (4 hours): Attack detail view + contract analysis**

- [ ] Build the kill chain visualization:
  - Use a step-flow diagram (boxes connected by arrows)
  - Each step shows: action type, transaction hash (linked to Etherscan), block number
  - Color-code: green for deployment, yellow for lure, red for drain
  - Show the "detection window" — how many seconds/blocks between token deployment and asset drain

- [ ] Build the transaction flow panel:
  - List all transactions in chronological order
  - Expandable: show internal calls for each transaction
  - Highlight the critical CALL that executed the drain

- [ ] Build the contract analysis view:
  - Risk assessment gauge (0-100)
  - Checklist of vulnerability indicators (tx.origin, unvalidated CALL, obfuscation level)
  - Attack history table
  - Recent interactions table

**Evening (2 hours): Polish and connect**

- [ ] Connect all frontend components to the FastAPI backend
- [ ] Add loading states, error handling
- [ ] Dark theme styling (security tool aesthetic)
- [ ] Responsive layout adjustments

---

### Day 3: Detection Polish + Demo Prep

**Morning (3 hours): Enhance detectors**

- [ ] Implement Module 2 (Pool-based detector) — simpler since only 3 cases
- [ ] Implement Module 3 (Refund-based detector) — focus on fallback function analysis
- [ ] Run full validation: process all 104 known attacks through all three detectors
- [ ] Build the "what-if" analysis:

```python
# what_if.py
class WhatIfAnalysis:
    def compute_prevention_stats(self) -> dict:
        """
        For each known attack:
        1. Would PhishNet have flagged the malicious contract?
        2. How long before the attack would the flag have appeared?
        3. How much could have been saved?
        
        Returns:
        {
            total_attacks: 104,
            detected: 87,           -- attacks our detector catches
            detection_rate: 0.837,
            total_loss: 2760000,    -- $2.76M
            preventable_loss: 2310000,  -- what we could have saved
            avg_warning_time: "4.2 blocks",  -- avg time between flag and drain
            by_type: {
                token: {detected: 85, total: 101},
                pool: {detected: 2, total: 3},
                refund: {detected: 0, total: 1}   -- hardest to catch
            }
        }
        """
```

- [ ] Add the "what-if" stats to the dashboard prominently

**Afternoon (3 hours): Demo scenario + real-time simulation**

- [ ] Build a demo mode that replays historical attacks in accelerated time:
  - Start from July 2021
  - Fast-forward through time, showing attacks appearing on the timeline
  - For each attack, show the detection feed flagging the malicious contract
  - Running counter of cumulative losses and how many PhishNet would have caught

- [ ] Prepare a specific walkthrough scenario:
  1. Show the dashboard with all 104 historical attacks
  2. Click on the largest attack (250 ETH / $636K)
  3. Walk through the kill chain step by step
  4. Show that PhishNet would have flagged the malicious token at deployment
  5. Navigate to the victim bot's contract analysis page
  6. Show it's still active with 142 ETH at risk (if applicable)
  7. Show the "what-if" statistics: "$2.45M could have been saved"

- [ ] Prepare for Q&A: have answers ready for:
  - "How do you reduce false positives?" → Anchored to known attacks, multi-signal scoring
  - "Can attackers evade detection?" → Discuss arms race, but many signals are structural
  - "What's the business model?" → Subscription monitoring for MEV operators
  - "How does this relate to the SKANF paper?" → We operationalize their findings
  - "What's next?" → Real-time mempool monitoring, automated defense (auto-revoke approvals)

**Evening (2 hours): Final polish**

- [ ] Test the full demo flow end-to-end 3 times
- [ ] Fix any rendering issues
- [ ] Write a 1-page project summary for judges
- [ ] Prepare 3-minute pitch script

---

## Demo Script (3 minutes)

**[0:00-0:30] The Problem**
"MEV bots on Ethereum hold millions in assets but many have critical vulnerabilities hidden by bytecode obfuscation. A recent Yale research paper discovered 104 phishing attacks totaling $2.76 million in losses — and only 3 were previously known. These attacks are ongoing. There's no monitoring system that watches for them."

**[0:30-1:00] The Solution**
"PhishNet is a real-time monitoring dashboard that detects MEV phishing attacks. We implemented three detection modules covering all three attack patterns identified in the research: token-based, pool-based, and refund-based phishing."

**[1:00-2:00] The Demo**
- Show the main dashboard with the attack timeline
- Click into the largest attack ($636K), walk through the kill chain
- Show the detection feed flagging the malicious token
- Show the risk leaderboard of vulnerable bots still active
- Highlight the "what-if" stat: "PhishNet would have prevented $X of $2.76M"

**[2:00-2:30] Technical Depth**
"Our token-based detector analyzes deployed bytecode for external CALLs with dangerous function selectors, cross-references against known MEV bot addresses, and scores risk using multiple signals. We validated against all 104 known attacks achieving an X% detection rate."

**[2:30-3:00] What's Next**
"PhishNet can become a subscription service for MEV operators — real-time alerts before attacks execute. We're exploring mempool monitoring for pre-execution detection and automated defense mechanisms. The $170 billion DeFi ecosystem needs this."

---

## Risk Mitigation

| Risk                           | Likelihood | Impact | Mitigation                                      |
|--------------------------------|-----------|--------|--------------------------------------------------|
| Dune query returns too many/few results | Medium | Medium | Use year-based queries to scope data; validate 2021 first before expanding |
| Dune credit limits (free plan) | Medium    | Medium | Top 500 bots (not 3271); year-by-year queries reduce per-query cost |
| Low detection rate on known attacks | Medium | High | Set realistic expectations; even 60% detection is valuable and novel |
| Frontend takes too long        | Low       | Medium | Use shadcn/ui components; skip animations; function over form |
| Etherscan API limits           | Low       | Low    | Cache aggressively; use free tier across multiple keys |

---

## Deliverables Checklist

- [ ] Working React dashboard with 3 main views
- [ ] FastAPI backend with detection engine
- [ ] SQLite database with enriched attack dataset
- [ ] Three detection modules (token, pool, refund)
- [ ] What-if analysis with prevention statistics
- [ ] Demo mode with historical replay
- [ ] 1-page project summary
- [ ] 3-minute pitch script
- [ ] GitHub repo with README

---

## Key Differentiators for Judges

1. **Novel dataset visualization** — First tool to make the SKANF paper's attack findings accessible and interactive
2. **Practical product** — Clear path to commercial monitoring service ($50K+ accelerator relevance)
3. **Validated detection** — Benchmarked against 104 real attacks, not theoretical
4. **Complementary to the research** — Operationalizes findings without trying to reproduce the research tool itself
5. **Visual storytelling** — Every data point has a narrative: attacker, victim, timeline, loss, what-if
