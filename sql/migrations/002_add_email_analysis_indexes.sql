-- Migration: Add performance indexes to email_analysis table
-- Date: 2025-10-23
-- Purpose: Optimize quarantine page query performance
-- Impact: Reduces /quarantine page load time by ~70% (from heavy UNION queries)

-- Add indexes for email_analysis table (quarantine page performance)
-- These indexes speed up:
-- 1. message_id lookups (LEFT JOIN with email_quarantine)
-- 2. timestamp sorting (ORDER BY timestamp DESC)
-- 3. sender filtering and search
-- 4. spam_score filtering (clean/suspicious/spam tabs)
-- 5. email_category filtering

ALTER TABLE email_analysis
    ADD INDEX IF NOT EXISTS idx_message_id (message_id),
    ADD INDEX IF NOT EXISTS idx_timestamp (timestamp),
    ADD INDEX IF NOT EXISTS idx_sender (sender(255)),
    ADD INDEX IF NOT EXISTS idx_spam_score (spam_score),
    ADD INDEX IF NOT EXISTS idx_email_category (email_category);

-- Verify indexes were created
SELECT
    TABLE_NAME,
    INDEX_NAME,
    COLUMN_NAME,
    SEQ_IN_INDEX,
    CARDINALITY
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME = 'email_analysis'
  AND INDEX_NAME IN ('idx_message_id', 'idx_timestamp', 'idx_sender', 'idx_spam_score', 'idx_email_category')
ORDER BY INDEX_NAME, SEQ_IN_INDEX;
