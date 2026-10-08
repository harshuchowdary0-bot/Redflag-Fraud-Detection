-- =====================================================================
-- RedFlag — Fraud Detection Submission
-- Student: B Harshitha | Batch: DA-DS-1
-- =====================================================================

USE redflag;

-- =====================================================================
-- PATTERN 1 · VELOCITY FRAUD
-- What I'm looking for: users with 30 or more transactions on one calendar day.
-- Expected suspects: ~50
-- =====================================================================

SELECT
    user_id,
    DATE(txn_time) AS attack_date,
    COUNT(*) AS daily_txn_count
FROM transactions
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY daily_txn_count DESC;

-- My findings: 50 suspect user-days were flagged. Examples include user 14569
-- with 60 transactions on 2024-04-03 and user 14556 with 60 transactions
-- on 2024-05-28.

-- =====================================================================
-- PATTERN 2 · ROUND-AMOUNT CLUSTERING
-- What I'm looking for: users with 15 or more transactions at the specified
-- exactly-round amounts.
-- Expected suspects: 25
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS round_txn_count
FROM transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY user_id
HAVING COUNT(*) >= 15
ORDER BY round_txn_count DESC;

-- My findings: 25 suspect users were flagged. Examples include user 14533
-- with 30 round-amount transactions (first observed on 2024-01-01) and
-- user 14535 with 30 (first observed on 2024-01-10).

-- =====================================================================
-- PATTERN 3 · CARD TESTING
-- What I'm looking for: users with 30 or more transactions under ₹10
-- on one calendar day.
-- Expected suspects: 20
-- =====================================================================

SELECT
    user_id,
    DATE(txn_time) AS attack_date,
    COUNT(*) AS tiny_txn_count
FROM transactions
WHERE amount < 10
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY tiny_txn_count DESC;

-- My findings: 20 suspect user-days were flagged. Examples include user 14556
-- with 60 tiny transactions on 2024-05-28 and user 14569 with 60 on
-- 2024-04-03.

-- =====================================================================
-- PATTERN 4 · FAILED-THEN-SUCCEEDED
-- What I'm looking for: users with 20 or more failed transactions that are
-- followed within 2 minutes by a successful transaction of the same amount.
-- Expected suspects: 25
-- =====================================================================

SELECT
    f.user_id,
    COUNT(*) AS failed_then_success_pairs
FROM transactions f
WHERE f.status = 'FAILED'
  AND EXISTS (
      SELECT 1
      FROM transactions s
      WHERE s.user_id = f.user_id
        AND s.status = 'SUCCESS'
        AND s.amount = f.amount
        AND s.txn_time > f.txn_time
        AND s.txn_time <= DATE_ADD(f.txn_time, INTERVAL 2 MINUTE)
  )
GROUP BY f.user_id
HAVING COUNT(*) >= 20
ORDER BY failed_then_success_pairs DESC;

-- My findings: 25 suspect users were flagged. Examples include user 14595
-- with 35 failed-then-success pairs, including a pair on 2024-05-25,
-- and user 14593 with 34 pairs, including pairs on 2024-04-19.

-- =====================================================================
-- PATTERN 5 · ODD-HOUR CONCENTRATION
-- What I'm looking for: users with at least 30 transactions where 80% or
-- more occur during hours 2, 3, or 4.
-- Expected suspects: 20
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS total_txns,
    SUM(
        CASE
            WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1
            ELSE 0
        END
    ) AS odd_hour_txns,
    ROUND(
        SUM(
            CASE
                WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1
                ELSE 0
            END
        ) / COUNT(*),
        4
    ) AS odd_hour_ratio
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 30
   AND SUM(
       CASE
           WHEN HOUR(txn_time) BETWEEN 2 AND 4 THEN 1
           ELSE 0
       END
   ) / COUNT(*) >= 0.80
ORDER BY odd_hour_ratio DESC;

-- My findings: 20 suspect users were flagged. Examples include user 14606
-- with 49 of 52 transactions in the odd-hour window and user 14609 with
-- 45 of 48 transactions in the same window.

-- =====================================================================
-- PATTERN 6 · MULE ACCOUNTS
-- What I'm looking for: users with at least 5 instances where a CREDIT through
-- NETBANKING is followed within 30 minutes by a DEBIT through UPI worth at
-- least 70% of the credited amount.
-- Expected suspects: 30
-- =====================================================================

SELECT
    c.user_id,
    COUNT(*) AS credit_to_debit_instances
FROM transactions c
WHERE c.txn_type = 'CREDIT'
  AND c.payment_mode = 'NETBANKING'
  AND EXISTS (
      SELECT 1
      FROM transactions d
      WHERE d.user_id = c.user_id
        AND d.txn_type = 'DEBIT'
        AND d.payment_mode = 'UPI'
        AND d.txn_time > c.txn_time
        AND d.txn_time <= DATE_ADD(c.txn_time, INTERVAL 30 MINUTE)
        AND d.amount >= c.amount * 0.70
  )
GROUP BY c.user_id
HAVING COUNT(*) >= 5
ORDER BY credit_to_debit_instances DESC;

-- My findings: 30 suspect users were flagged. Examples include user 14621,
-- which has multiple qualifying credit-to-debit instances, including one
-- beginning on 2024-01-18.

-- =====================================================================
-- PATTERN 7 · REFUND ABUSE
-- What I'm looking for: users with 20 or more total transactions and a refund
-- ratio greater than 40%.
-- Expected suspects: 24-25
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS total_txns,
    SUM(
        CASE
            WHEN txn_type = 'REFUND' THEN 1
            ELSE 0
        END
    ) AS refund_txns,
    ROUND(
        SUM(
            CASE
                WHEN txn_type = 'REFUND' THEN 1
                ELSE 0
            END
        ) / COUNT(*),
        4
    ) AS refund_ratio
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 20
   AND SUM(
       CASE
           WHEN txn_type = 'REFUND' THEN 1
           ELSE 0
       END
   ) / COUNT(*) > 0.40
ORDER BY refund_ratio DESC;

-- My findings: 24 suspect users were flagged. Examples include user 14662
-- with 25 refunds out of 39 transactions, with refund activity from
-- 2024-01-08 to 2024-06-03, and user 14670 with 32 refunds out of 50
-- transactions.

-- =====================================================================
-- PATTERN 8 · MERCHANT COLLUSION
-- What I'm looking for: merchants where the top 5 users by transaction value
-- account for more than 60% of the merchant's total transaction value.
-- Expected suspects: 15 merchants
-- =====================================================================

WITH user_merchant_volume AS (
    SELECT
        merchant_id,
        user_id,
        SUM(amount) AS user_volume
    FROM transactions
    GROUP BY merchant_id, user_id
),
ranked_users AS (
    SELECT
        merchant_id,
        user_id,
        user_volume,
        ROW_NUMBER() OVER (
            PARTITION BY merchant_id
            ORDER BY user_volume DESC, user_id
        ) AS user_rank
    FROM user_merchant_volume
),
merchant_totals AS (
    SELECT
        merchant_id,
        SUM(amount) AS merchant_total
    FROM transactions
    GROUP BY merchant_id
),
top_five AS (
    SELECT
        merchant_id,
        SUM(user_volume) AS top5_volume
    FROM ranked_users
    WHERE user_rank <= 5
    GROUP BY merchant_id
)
SELECT
    t.merchant_id,
    t.top5_volume,
    m.merchant_total,
    ROUND(t.top5_volume / m.merchant_total, 4) AS top5_volume_ratio
FROM top_five t
JOIN merchant_totals m
    ON m.merchant_id = t.merchant_id
WHERE t.top5_volume / m.merchant_total > 0.60
ORDER BY top5_volume_ratio DESC;

-- My findings: 15 suspect merchants were flagged. The flagged merchants are
-- merchant IDs 1 through 15; for example, merchant 12 has a top-five volume
-- ratio of about 99.91%, and merchant 8 has about 99.87%.

-- =====================================================================
-- PATTERN 9 · JUST-UNDER-THRESHOLD (STRUCTURING)
-- What I'm looking for: users with 10 or more transactions at exactly ₹9,999.
-- Expected suspects: 20
-- =====================================================================

SELECT
    user_id,
    COUNT(*) AS threshold_txn_count
FROM transactions
WHERE amount = 9999.00
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY threshold_txn_count DESC;

-- My findings: 20 suspect users were flagged. Examples include user 14690
-- with 25 transactions at ₹9,999, with activity from 2024-01-13 to
-- 2024-06-18, and user 14680 with 25 such transactions.

-- =====================================================================
-- PATTERN 10 · DORMANT-THEN-ACTIVE
-- What I'm looking for: users with a 90+ day gap between consecutive
-- transactions followed by at least 15 transactions after reactivation.
-- Expected suspects: 25-27
-- =====================================================================

WITH ordered_transactions AS (
    SELECT
        user_id,
        txn_time,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS prev_time
    FROM transactions
),
dormant_gaps AS (
    SELECT
        user_id,
        prev_time AS dormant_from,
        txn_time AS reactivation_time
    FROM ordered_transactions
    WHERE prev_time IS NOT NULL
      AND TIMESTAMPDIFF(DAY, prev_time, txn_time) >= 90
),
flagged_gaps AS (
    SELECT
        g.user_id,
        g.dormant_from,
        g.reactivation_time,
        TIMESTAMPDIFF(
            DAY,
            g.dormant_from,
            g.reactivation_time
        ) AS dormant_gap_days,
        (
            SELECT COUNT(*)
            FROM transactions t
            WHERE t.user_id = g.user_id
              AND t.txn_time >= g.reactivation_time
        ) AS post_gap_txn_count
    FROM dormant_gaps g
)
SELECT
    user_id,
    dormant_from,
    reactivation_time,
    dormant_gap_days,
    post_gap_txn_count
FROM flagged_gaps
WHERE post_gap_txn_count >= 15
ORDER BY post_gap_txn_count DESC;

-- My findings: 26 suspect user-gaps were flagged. Examples include user 14526,
-- with a 102-day gap ending on 2024-05-20 and 55 transactions afterward,
-- and user 14701, with a 135-day gap ending on 2024-06-05 and 28 transactions
-- afterward.

-- =====================================================================
-- PATTERN 11 · VELOCITY SPIKE
-- What I'm looking for: users whose peak monthly transaction count is at least
-- 5 times their average monthly count, with a peak of at least 20 transactions.
-- Expected suspects: 35-45
-- =====================================================================

WITH months AS (
    SELECT '2024-01' AS month_key
    UNION ALL SELECT '2024-02'
    UNION ALL SELECT '2024-03'
    UNION ALL SELECT '2024-04'
    UNION ALL SELECT '2024-05'
    UNION ALL SELECT '2024-06'
),
monthly_counts AS (
    SELECT
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m') AS month_key,
        COUNT(*) AS monthly_txn_count
    FROM transactions
    GROUP BY user_id, DATE_FORMAT(txn_time, '%Y-%m')
),
user_months AS (
    SELECT
        u.user_id,
        m.month_key,
        COALESCE(mc.monthly_txn_count, 0) AS monthly_txn_count
    FROM (
        SELECT DISTINCT user_id
        FROM transactions
    ) u
    CROSS JOIN months m
    LEFT JOIN monthly_counts mc
        ON mc.user_id = u.user_id
       AND mc.month_key = m.month_key
),
user_summary AS (
    SELECT
        user_id,
        AVG(monthly_txn_count) AS avg_monthly_txns,
        MAX(monthly_txn_count) AS peak_monthly_txns,
        SUM(
            CASE
                WHEN monthly_txn_count > 0 THEN 1
                ELSE 0
            END
        ) AS active_months
    FROM user_months
    GROUP BY user_id
),
final_summary AS (
    SELECT
        user_id,
        avg_monthly_txns,
        peak_monthly_txns,
        active_months,
        peak_monthly_txns / NULLIF(avg_monthly_txns, 0) AS peak_avg_ratio
    FROM user_summary
)
SELECT
    user_id,
    ROUND(avg_monthly_txns, 2) AS avg_monthly_txns,
    peak_monthly_txns,
    active_months,
    ROUND(peak_avg_ratio, 2) AS peak_avg_ratio
FROM final_summary
WHERE peak_monthly_txns >= 20
  AND active_months >= 2
  AND peak_avg_ratio > 5
ORDER BY peak_avg_ratio DESC;

-- My findings: 43 suspect users were flagged. Examples include user 14520,
-- whose peak month was 2024-01 with 52 transactions, user 14511, whose
-- peak month was 2024-06 with 46 transactions, and user 14509, whose
-- peak month was 2024-02 with 36 transactions.

-- =====================================================================
-- PATTERN 12 · GEOGRAPHIC IMPOSSIBILITY
-- What I'm looking for: users whose consecutive transactions occur in
-- different cities within 60 minutes.
-- Expected suspects: 15
-- =====================================================================

WITH ordered_transactions AS (
    SELECT
        user_id,
        txn_time,
        city,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS prev_time,
        LAG(city) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS prev_city
    FROM transactions
)
SELECT
    user_id,
    prev_city,
    city AS current_city,
    prev_time,
    txn_time AS current_txn_time,
    TIMESTAMPDIFF(MINUTE, prev_time, txn_time) AS gap_minutes
FROM ordered_transactions
WHERE prev_time IS NOT NULL
  AND prev_city <> city
  AND TIMESTAMPDIFF(MINUTE, prev_time, txn_time) <= 60
ORDER BY gap_minutes ASC;

-- My findings: 15 suspect users were flagged. Examples include user 14750,
-- moving from Visakhapatnam to Delhi in 1 minute 45 seconds on 2024-06-18,
-- and user 14745, moving from Surat to Thiruvananthapuram in 9 minutes
-- 24 seconds on 2024-05-07.

-- =====================================================================
-- END OF REDFLAG SUBMISSION
-- =====================================================================
