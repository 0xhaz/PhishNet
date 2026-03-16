-- Query 3: Attack Timeline Aggregation
-- Monthly bucketed attack counts and total losses for the dashboard chart.
-- Uses the same drain detection logic as query 02, then aggregates by month.
--
-- Parameters:
--   {{start_date}}   e.g. 2021-01-01
--   {{end_date}}     e.g. 2021-12-31

WITH -- <<BEGIN KNOWN_BOTS>>
known_bots AS (
    -- Reads from uploaded Dune dataset: dune.watekungsik.dataset_known_mev_bots
    -- Upload via: python scripts/inject_bot_addresses.py --upload
    -- Total addresses in dataset: 3271
    SELECT from_hex(address) AS address FROM dune.watekungsik.dataset_known_mev_bots
), -- <<END KNOWN_BOTS>>

WETH_ADDRESS AS (
    SELECT 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 AS addr
),

-- ETH drains from known bots
eth_drains AS (
    SELECT
        tr.block_time,
        tr.tx_hash,
        tr."from"           AS victim_bot,
        tr.value / 1e18     AS loss_eth,
        'ETH'               AS asset
    FROM ethereum.traces tr
    JOIN known_bots kb ON tr."from" = kb.address
    WHERE tr.block_time BETWEEN TIMESTAMP '{{start_date}}' AND TIMESTAMP '{{end_date}}'
      AND tr.call_type = 'call'
      AND tr.value / 1e18 >= 1
      AND tr.success = TRUE
),

-- WETH drains from known bots
weth_drains AS (
    SELECT
        l.block_time,
        l.tx_hash,
        bytearray_substring(l.topic1, 13, 20)  AS victim_bot,
        bytearray_to_uint256(l.data) / 1e18     AS loss_eth,
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

-- Join with ETH price for USD conversion
with_usd AS (
    SELECT
        d.*,
        d.loss_eth * COALESCE(p.price, 2500)  AS loss_usd
    FROM all_drains d
    LEFT JOIN prices.usd p
        ON p.contract_address = 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
        AND p.minute = date_trunc('minute', d.block_time)
),

monthly AS (
    SELECT
        date_trunc('month', block_time)  AS month,
        asset                            AS attack_type,
        COUNT(*)                         AS attack_count,
        SUM(loss_eth)                    AS total_loss_eth,
        SUM(loss_usd)                    AS total_loss_usd
    FROM with_usd
    GROUP BY 1, 2
)

SELECT
    month,
    attack_type,
    attack_count,
    ROUND(total_loss_eth, 4)   AS total_loss_eth,
    ROUND(total_loss_usd, 2)   AS total_loss_usd,
    SUM(attack_count)  OVER (ORDER BY month)            AS cumulative_attacks,
    SUM(total_loss_usd) OVER (ORDER BY month)           AS cumulative_loss_usd
FROM monthly
ORDER BY month ASC
;
