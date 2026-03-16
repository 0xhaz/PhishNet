-- Query 4: Vulnerable Bots Ranked by Current ETH Balance
-- Identifies MEV bots that have had ETH/WETH drained, ranks by approx balance.
--
-- NOTE: Dune doesn't expose live balances; we approximate via
-- cumulative ETH in minus ETH out over a recent window.
-- For accurate current balances, supplement with Etherscan in seed_db.py.
--
-- Parameters:
--   {{start_date}}       e.g. 2021-01-01
--   {{end_date}}         e.g. 2021-12-31

WITH -- <<BEGIN KNOWN_BOTS>>
known_bots AS (
    -- Reads from uploaded Dune dataset: dune.watekungsik.dataset_known_mev_bots
    -- Upload via: python scripts/inject_bot_addresses.py --upload
    -- Total addresses in dataset: 3271
    SELECT from_hex(address) AS address, label FROM dune.watekungsik.dataset_known_mev_bots
), -- <<END KNOWN_BOTS>>

WETH_ADDRESS AS (
    SELECT 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 AS addr
),

-- ETH drains from known bots in the date range
eth_drains AS (
    SELECT
        tr."from"           AS victim_bot,
        tr.value / 1e18     AS loss_eth,
        tr.block_time,
        'ETH'               AS asset
    FROM ethereum.traces tr
    JOIN known_bots kb ON tr."from" = kb.address
    WHERE tr.block_time BETWEEN TIMESTAMP '{{start_date}}' AND TIMESTAMP '{{end_date}}'
      AND tr.call_type = 'call'
      AND tr.value / 1e18 >= 1
      AND tr.success = TRUE
),

-- WETH drains from known bots in the date range
weth_drains AS (
    SELECT
        bytearray_substring(l.topic1, 13, 20)  AS victim_bot,
        bytearray_to_uint256(l.data) / 1e18     AS loss_eth,
        l.block_time,
        'WETH'                                  AS asset
    FROM ethereum.logs l
    JOIN known_bots kb
        ON bytearray_substring(l.topic1, 13, 20) = kb.address
    WHERE l.contract_address = (SELECT addr FROM WETH_ADDRESS)
      AND l.topic0 = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
      AND l.block_time BETWEEN TIMESTAMP '{{start_date}}' AND TIMESTAMP '{{end_date}}'
      AND bytearray_to_uint256(l.data) / 1e18 >= 1
),

all_drains AS (
    SELECT * FROM eth_drains
    UNION ALL
    SELECT * FROM weth_drains
),

-- Attack stats per bot
attack_stats AS (
    SELECT
        victim_bot          AS address,
        COUNT(*)            AS attack_count,
        SUM(loss_eth)       AS total_loss_eth,
        MAX(block_time)     AS last_attack_at,
        ARRAY_JOIN(ARRAY_AGG(DISTINCT asset), ', ') AS attack_types
    FROM all_drains
    GROUP BY victim_bot
),

-- Approximate ETH balance from traces (scoped to date range)
eth_received AS (
    SELECT
        tr."to"          AS address,
        SUM(tr.value / 1e18) AS total_received
    FROM ethereum.traces tr
    JOIN known_bots kb ON tr."to" = kb.address
    WHERE tr.block_time BETWEEN TIMESTAMP '{{start_date}}' AND TIMESTAMP '{{end_date}}'
      AND tr.success = TRUE
    GROUP BY tr."to"
),

eth_sent AS (
    SELECT
        tr."from"        AS address,
        SUM(tr.value / 1e18) AS total_sent
    FROM ethereum.traces tr
    JOIN known_bots kb ON tr."from" = kb.address
    WHERE tr.block_time BETWEEN TIMESTAMP '{{start_date}}' AND TIMESTAMP '{{end_date}}'
      AND tr.success = TRUE
    GROUP BY tr."from"
)

SELECT
    kb.address,
    kb.label,
    COALESCE(er.total_received, 0) - COALESCE(es.total_sent, 0)  AS approx_balance_eth,
    COALESCE(ast.attack_count, 0)                                 AS attack_count,
    COALESCE(ast.total_loss_eth, 0)                               AS total_loss_eth,
    ast.last_attack_at,
    ast.attack_types,
    CASE
        WHEN ast.attack_count >= 3 THEN 'HIGH'
        WHEN ast.attack_count >= 1 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS risk_level
FROM known_bots kb
LEFT JOIN attack_stats ast ON ast.address = kb.address
LEFT JOIN eth_received    er ON er.address  = kb.address
LEFT JOIN eth_sent        es ON es.address  = kb.address
WHERE COALESCE(er.total_received, 0) - COALESCE(es.total_sent, 0) >= 1
ORDER BY approx_balance_eth DESC
LIMIT 10000
;
