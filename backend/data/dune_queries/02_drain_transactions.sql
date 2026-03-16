-- Query 2: Asset Drain Transactions
-- Given a set of known victim bots and a date range, find transactions where
-- large amounts of ETH or WETH left the bot to an external (non-contract) address
-- within a short window after a token was received.
--
-- This reconstructs Step 3 (drain) of the kill chain.
-- Parameters:
--   {{start_date}}        e.g. 2021-07-01
--   {{end_date}}          e.g. 2025-04-30
--   {{min_drain_eth}}     e.g. 1   (minimum ETH drained to count)

WITH -- <<BEGIN KNOWN_BOTS>>
known_bots AS (
    -- Reads from uploaded Dune dataset: dune.watekungsik.dataset_known_mev_bots
    -- Upload via: python scripts/inject_bot_addresses.py --upload
    -- Total addresses in dataset: 3271
    SELECT from_hex(address) AS address FROM dune.watekungsik.dataset_known_mev_bots
), -- <<END KNOWN_BOTS>>,

WETH_ADDRESS AS (
    SELECT 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 AS addr
),

-- Well-known contracts that are NOT attackers (routers, WETH, exchanges, etc.)
safe_recipients AS (
    SELECT addr FROM (VALUES
        (0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2),  -- WETH
        (0x7a250d5630b4cf539739df2c5dacb4c659f2488d),  -- Uniswap V2 Router
        (0xe592427a0aece92de3edee1f18e0157c05861564),  -- Uniswap V3 Router
        (0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45),  -- Uniswap V3 Router 02
        (0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b),  -- Uniswap Universal Router
        (0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad),  -- Uniswap Universal Router 2
        (0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f),  -- SushiSwap Router
        (0x1111111254fb6c44bac0bed2854e76f90643097d),  -- 1inch v4
        (0x1111111254eeb25477b68fb85ed929f73a960582),  -- 1inch v5
        (0xdef1c0ded9bec7f1a1670819833240f027b25eff),  -- 0x Exchange Proxy
        (0x00000000219ab540356cbb839cbe05303d7705fa),  -- ETH2 Deposit
        (0x7f268357a8c2552623316e2562d90e642bb538e5),  -- OpenSea (Wyvern)
        (0x00000000006c3852cbef3e08e8df289169ede581),  -- Seaport 1.1
        (0xc36442b4a4522e871399cd717abdd847ab11fe88),  -- Uniswap V3 NFT Manager
        (0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD)   -- Uniswap Universal Router 2
    ) AS t(addr)
),

-- Internal ETH calls FROM known bots TO external addresses
-- Excludes transfers to well-known contracts (WETH wraps, DEX swaps, etc.)
eth_drains AS (
    SELECT
        tr.block_time,
        tr.block_number,
        tr.tx_hash,
        tr."from"           AS bot_address,
        tr."to"             AS recipient,
        tr.value / 1e18     AS eth_amount,
        'ETH'               AS asset
    FROM ethereum.traces tr
    JOIN known_bots kb ON tr."from" = kb.address
    LEFT JOIN safe_recipients sr ON tr."to" = sr.addr
    WHERE tr.block_time BETWEEN TIMESTAMP '{{start_date}}' AND TIMESTAMP '{{end_date}}'
      AND tr.call_type = 'call'
      AND tr.value / 1e18 >= 1
      AND tr.success = TRUE
      AND sr.addr IS NULL  -- exclude transfers to safe contracts
),

-- WETH Transfer events FROM known bots (excluding transfers to safe recipients)
weth_drains AS (
    SELECT
        l.block_time,
        l.block_number,
        l.tx_hash,
        bytearray_substring(l.topic1, 13, 20)  AS bot_address,
        bytearray_substring(l.topic2, 13, 20)  AS recipient,
        bytearray_to_uint256(l.data) / 1e18     AS eth_amount,
        'WETH'                                  AS asset
    FROM ethereum.logs l
    JOIN known_bots kb
        ON bytearray_substring(l.topic1, 13, 20) = kb.address
    LEFT JOIN safe_recipients sr
        ON bytearray_substring(l.topic2, 13, 20) = sr.addr
    WHERE l.contract_address = (SELECT addr FROM WETH_ADDRESS)
      AND l.topic0 = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
      AND l.block_time BETWEEN TIMESTAMP '{{start_date}}' AND TIMESTAMP '{{end_date}}'
      AND bytearray_to_uint256(l.data) / 1e18 >= 1
      AND sr.addr IS NULL  -- exclude transfers to safe contracts
),

all_drains AS (
    SELECT * FROM eth_drains
    UNION ALL
    SELECT * FROM weth_drains
),

-- Keep top 5 drains per bot so every bot gets representation
ranked AS (
    SELECT
        d.*,
        ROW_NUMBER() OVER (PARTITION BY d.bot_address ORDER BY d.eth_amount DESC) AS rn
    FROM all_drains d
),

filtered AS (
    SELECT * FROM ranked WHERE rn <= 5
),

-- Find who called the bot in each drain tx (the attacking contract / EOA)
-- In a tx.origin attack: attacker_contract calls bot → bot sends ETH out
bot_callers AS (
    SELECT
        tr.tx_hash,
        tr."from" AS caller
    FROM ethereum.traces tr
    JOIN filtered f
        ON tr.tx_hash = f.tx_hash
        AND tr."to" = f.bot_address
    WHERE tr.call_type = 'call'
      AND tr."from" != f.bot_address  -- exclude self-calls
),

-- Find the DeFi contract the bot pulled funds from in the same tx
-- e.g. Balancer pool, Uniswap pair, Aave lending pool, etc.
fund_sources AS (
    SELECT
        tr.tx_hash,
        tr."to" AS source_contract
    FROM ethereum.traces tr
    JOIN filtered f
        ON tr.tx_hash = f.tx_hash
        AND tr."from" = f.bot_address  -- bot called this contract
    WHERE tr.call_type = 'call'
      AND tr."to" != f.recipient       -- not the drain destination
      AND tr."to" != f.bot_address     -- not self-call
)

SELECT
    d.block_time,
    d.block_number,
    d.tx_hash,
    d.bot_address,
    d.recipient,
    d.eth_amount,
    d.asset,
    d.rn AS drain_rank,
    p.price * d.eth_amount AS approx_usd,
    bc.caller AS attacker_contract,
    fs.source_contract
FROM filtered d
LEFT JOIN prices.usd p
    ON p.contract_address = 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
    AND p.minute = date_trunc('minute', d.block_time)
LEFT JOIN bot_callers bc
    ON bc.tx_hash = d.tx_hash
LEFT JOIN fund_sources fs
    ON fs.tx_hash = d.tx_hash
ORDER BY d.eth_amount DESC
;
