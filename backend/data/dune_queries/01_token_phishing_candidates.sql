-- Query 1: Token-Based Phishing Candidates (with false-positive filtering)
-- Finds ERC-20 contracts that were:
--   (a) deployed within the date range, AND
--   (b) had their first Transfer event go to a known MEV bot address, AND
--   (c) exhibit phishing-like traits (fast lure, low transfers, serial deployer)
--
-- Parameters:
--   {{start_date}}  e.g. 2021-01-01
--   {{end_date}}    e.g. 2021-12-31

WITH -- <<BEGIN KNOWN_BOTS>>
known_bots AS (
    -- Reads from uploaded Dune dataset: dune.watekungsik.dataset_known_mev_bots
    -- Upload via: python scripts/inject_bot_addresses.py --upload
    -- Total addresses in dataset: 3271
    SELECT from_hex(address) AS address FROM dune.watekungsik.dataset_known_mev_bots
), -- <<END KNOWN_BOTS>>

-- All ERC-20 Transfer events in the date window
transfers AS (
    SELECT
        t.contract_address  AS token_address,
        t.block_time,
        t.block_number,
        t.tx_hash,
        bytearray_to_uint256(t.data)           AS amount,
        bytearray_substring(t.topic2, 13, 20)  AS to_address,
        bytearray_substring(t.topic1, 13, 20)  AS from_address
    FROM ethereum.logs t
    WHERE t.topic0 = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
      AND t.block_time BETWEEN TIMESTAMP '{{start_date}}' AND TIMESTAMP '{{end_date}}'
),

-- Contracts deployed in the same window
deployed AS (
    SELECT
        address      AS token_address,
        block_time   AS deployed_at,
        block_number AS deploy_block,
        tx_hash      AS deploy_tx,
        "from"       AS deployer
    FROM ethereum.creation_traces
    WHERE block_time BETWEEN TIMESTAMP '{{start_date}}' AND TIMESTAMP '{{end_date}}'
),

-- First Transfer event per token
first_transfer AS (
    SELECT
        token_address,
        MIN(block_number) AS first_transfer_block,
        MIN_BY(to_address,   block_number) AS first_recipient,
        MIN_BY(tx_hash,      block_number) AS first_transfer_tx
    FROM transfers
    GROUP BY token_address
),

-- Transfer stats per token (holder count, total transfers)
transfer_stats AS (
    SELECT
        token_address,
        COUNT(*)                                        AS total_transfers,
        COUNT(DISTINCT to_address)                      AS unique_holders,
        MAX(block_time) - MIN(block_time)               AS activity_window
    FROM transfers
    GROUP BY token_address
),

-- Serial deployer detection: deployers who created 3+ contracts
deployer_stats AS (
    SELECT
        deployer,
        COUNT(DISTINCT token_address) AS contracts_deployed
    FROM deployed
    GROUP BY deployer
),

-- Join: token deployed → first transfer goes to a known MEV bot
phishing_candidates AS (
    SELECT
        d.token_address,
        d.deployed_at,
        d.deploy_tx,
        d.deployer,
        d.deploy_block,
        ft.first_transfer_block,
        ft.first_recipient              AS targeted_bot,
        ft.first_transfer_tx,
        (ft.first_transfer_block - d.deploy_block) AS blocks_until_lure,
        COALESCE(ts.total_transfers, 0)             AS total_transfers,
        COALESCE(ts.unique_holders, 0)              AS unique_holders,
        COALESCE(ds.contracts_deployed, 0)          AS deployer_contract_count
    FROM deployed d
    JOIN first_transfer ft
        ON ft.token_address = d.token_address
    JOIN known_bots kb
        ON ft.first_recipient = kb.address
    LEFT JOIN transfer_stats ts
        ON ts.token_address = d.token_address
    LEFT JOIN deployer_stats ds
        ON ds.deployer = d.deployer
)

SELECT
    token_address,
    deployed_at,
    deploy_tx,
    deployer,
    deploy_block,
    targeted_bot,
    first_transfer_tx,
    first_transfer_block,
    blocks_until_lure,
    CAST(blocks_until_lure * 12 AS BIGINT) AS seconds_until_lure,
    total_transfers,
    unique_holders,
    deployer_contract_count,

    -- Dynamic risk score (0-100)
    (
        -- Fast lure: closer to deploy = more suspicious (max 30 pts)
        CASE
            WHEN blocks_until_lure <= 5   THEN 30
            WHEN blocks_until_lure <= 20  THEN 25
            WHEN blocks_until_lure <= 100 THEN 15
            ELSE 5
        END
        -- Low transfers: phishing tokens have very few (max 25 pts)
        + CASE
            WHEN total_transfers <= 5   THEN 25
            WHEN total_transfers <= 20  THEN 20
            WHEN total_transfers <= 50  THEN 10
            ELSE 0
        END
        -- Low holders: scam tokens have < 10 unique recipients (max 20 pts)
        + CASE
            WHEN unique_holders <= 3  THEN 20
            WHEN unique_holders <= 10 THEN 15
            WHEN unique_holders <= 20 THEN 5
            ELSE 0
        END
        -- Serial deployer: same address deploys many contracts (max 25 pts)
        + CASE
            WHEN deployer_contract_count >= 10 THEN 25
            WHEN deployer_contract_count >= 5  THEN 20
            WHEN deployer_contract_count >= 3  THEN 10
            ELSE 0
        END
    ) AS risk_score

FROM phishing_candidates
-- Filter out obvious false positives:
-- Legit tokens have 100s of transfers and many holders
WHERE blocks_until_lure <= 200           -- lure within ~40 min of deploy
   OR total_transfers <= 50              -- low activity token
   OR deployer_contract_count >= 3       -- serial deployer
ORDER BY risk_score DESC, deployed_at DESC
;
