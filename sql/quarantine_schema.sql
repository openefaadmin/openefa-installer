-- ============================================================================
-- OpenEFA Quarantine System - Database Schema
-- ============================================================================
-- Version: 1.0
-- Date: 2025-10-13
--
-- Note: Database name is specified at import time via mysql -u root "${DB_NAME}"
-- ============================================================================

-- ============================================================================
-- TABLE: email_quarantine
-- Primary quarantine storage for blocked emails
-- ============================================================================
CREATE TABLE IF NOT EXISTS email_quarantine (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Email identification
    message_id VARCHAR(255) UNIQUE NOT NULL,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Quarantine status
    quarantine_status ENUM('held', 'released', 'deleted', 'expired') DEFAULT 'held',
    quarantine_reason VARCHAR(100) COMMENT 'spam, virus, policy, manual',
    quarantine_expires_at DATETIME NOT NULL,

    -- User classification (for learning)
    user_classification ENUM('spam', 'not_spam', 'uncertain') DEFAULT NULL,
    reviewed_by VARCHAR(100),
    reviewed_at DATETIME,

    -- Email metadata
    sender VARCHAR(255) NOT NULL,
    sender_domain VARCHAR(255),
    recipients TEXT COMMENT 'JSON array',
    recipient_domains TEXT COMMENT 'JSON array',
    subject VARCHAR(500),

    -- Content storage
    raw_email LONGTEXT NOT NULL COMMENT 'Full RFC822 message',
    email_size INT COMMENT 'Size in bytes',
    text_content MEDIUMTEXT,
    html_content LONGTEXT,

    -- Attachments
    has_attachments BOOLEAN DEFAULT FALSE,
    attachment_count INT DEFAULT 0,
    attachment_names TEXT COMMENT 'JSON array',

    -- Spam analysis details
    spam_score DECIMAL(5,2),
    spam_modules_detail TEXT COMMENT 'JSON with module scores',
    virus_detected BOOLEAN DEFAULT FALSE,
    virus_names TEXT COMMENT 'JSON array',
    phishing_detected BOOLEAN DEFAULT FALSE,

    -- Authentication results
    spf_result VARCHAR(20),
    dkim_result VARCHAR(20),
    dmarc_result VARCHAR(20),
    auth_score DECIMAL(5,2),

    -- Actions
    released_by VARCHAR(100),
    released_at DATETIME,
    released_to VARCHAR(100) COMMENT 'mailguard or zimbra',
    deleted_by VARCHAR(100),
    deleted_at DATETIME,

    -- Notes
    admin_notes TEXT,

    -- Indexes for performance
    INDEX idx_status (quarantine_status),
    INDEX idx_expires (quarantine_expires_at),
    INDEX idx_sender (sender),
    INDEX idx_sender_domain (sender_domain),
    INDEX idx_timestamp (timestamp),
    INDEX idx_spam_score (spam_score),
    INDEX idx_reviewed (reviewed_by, reviewed_at)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Email quarantine storage with 30-day default retention';


-- ============================================================================
-- TABLE: quarantine_actions_log
-- Audit trail for all quarantine operations
-- ============================================================================
CREATE TABLE IF NOT EXISTS quarantine_actions_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    quarantine_id INT NOT NULL,
    FOREIGN KEY (quarantine_id) REFERENCES email_quarantine(id) ON DELETE CASCADE,

    -- Action details
    action_type ENUM(
        'quarantined', 'released', 'deleted', 'reviewed',
        'marked_spam', 'marked_not_spam', 'whitelisted',
        'expired', 'admin_note_added'
    ) NOT NULL,
    action_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- User who performed action
    performed_by VARCHAR(100) NOT NULL,
    user_role VARCHAR(50),
    user_ip VARCHAR(45) COMMENT 'IPv6 support',

    -- Action details
    action_details TEXT COMMENT 'JSON with additional context',
    reason TEXT,

    -- Indexes
    INDEX idx_quarantine_id (quarantine_id),
    INDEX idx_timestamp (action_timestamp),
    INDEX idx_performed_by (performed_by),
    INDEX idx_action_type (action_type)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Audit log for all quarantine operations';


-- ============================================================================
-- TABLE: quarantine_statistics
-- Daily statistics for reporting
-- ============================================================================
CREATE TABLE IF NOT EXISTS quarantine_statistics (
    id INT AUTO_INCREMENT PRIMARY KEY,

    -- Time period
    stat_date DATE NOT NULL,

    -- Domain
    domain VARCHAR(255),

    -- Metrics
    emails_quarantined INT DEFAULT 0,
    emails_released INT DEFAULT 0,
    emails_deleted INT DEFAULT 0,
    emails_expired INT DEFAULT 0,

    -- By classification
    user_marked_spam INT DEFAULT 0,
    user_marked_not_spam INT DEFAULT 0,

    -- Scores
    avg_spam_score DECIMAL(5,2),
    max_spam_score DECIMAL(5,2),
    min_spam_score DECIMAL(5,2),

    -- Storage
    total_size_bytes BIGINT DEFAULT 0,

    -- Indexes
    UNIQUE INDEX idx_stat_date_domain (stat_date, domain),
    INDEX idx_date (stat_date),
    INDEX idx_domain (domain)

) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Daily quarantine statistics for reporting';


-- ============================================================================
-- TABLE: quarantine_config
-- System configuration for quarantine
-- ============================================================================
CREATE TABLE IF NOT EXISTS quarantine_config (
    id INT AUTO_INCREMENT PRIMARY KEY,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT NOT NULL,
    description TEXT,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    updated_by VARCHAR(100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
COMMENT='Quarantine system configuration';


-- ============================================================================
-- INSERT DEFAULT CONFIGURATION
-- ============================================================================
INSERT INTO quarantine_config (config_key, config_value, description) VALUES
('default_retention_days', '30', 'Default quarantine retention period in days'),
('release_destination', 'mailguard', 'Where to release emails: mailguard or zimbra'),
('mailguard_host', '192.168.50.37', 'MailGuard server IP'),
('mailguard_port', '25', 'MailGuard SMTP port'),
('zimbra_host', '', 'Zimbra server IP (for future direct relay)'),
('zimbra_port', '25', 'Zimbra SMTP port'),
('spam_threshold', '5.0', 'Spam score threshold for quarantine'),
('auto_prune_enabled', 'true', 'Enable automatic pruning of expired emails'),
('premium_retention_years', '7', 'Retention period for premium customers')
ON DUPLICATE KEY UPDATE config_key=config_key;


-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- Active quarantine view
CREATE OR REPLACE VIEW v_active_quarantine AS
SELECT
    q.*,
    DATEDIFF(q.quarantine_expires_at, NOW()) as days_until_expiry,
    (SELECT COUNT(*) FROM quarantine_actions_log WHERE quarantine_id = q.id) as action_count
FROM email_quarantine q
WHERE q.quarantine_status = 'held'
  AND q.quarantine_expires_at > NOW()
ORDER BY q.timestamp DESC;


-- Quarantine summary by domain
CREATE OR REPLACE VIEW v_quarantine_summary_by_domain AS
SELECT
    sender_domain,
    COUNT(*) as total_quarantined,
    SUM(CASE WHEN quarantine_status = 'held' THEN 1 ELSE 0 END) as currently_held,
    SUM(CASE WHEN quarantine_status = 'released' THEN 1 ELSE 0 END) as total_released,
    SUM(CASE WHEN quarantine_status = 'deleted' THEN 1 ELSE 0 END) as total_deleted,
    AVG(spam_score) as avg_spam_score,
    MAX(timestamp) as last_quarantine_time
FROM email_quarantine
GROUP BY sender_domain
ORDER BY total_quarantined DESC;


-- Recent actions view
CREATE OR REPLACE VIEW v_recent_quarantine_actions AS
SELECT
    l.id as log_id,
    l.action_type,
    l.action_timestamp,
    l.performed_by,
    l.user_role,
    q.message_id,
    q.sender,
    q.subject,
    q.spam_score
FROM quarantine_actions_log l
JOIN email_quarantine q ON l.quarantine_id = q.id
ORDER BY l.action_timestamp DESC
LIMIT 100;


-- ============================================================================
-- STORED PROCEDURES
-- ============================================================================

-- Procedure to prune expired emails
DELIMITER $$

CREATE PROCEDURE IF NOT EXISTS prune_expired_quarantine()
BEGIN
    DECLARE deleted_count INT DEFAULT 0;
    DECLARE is_premium BOOLEAN DEFAULT FALSE;

    -- Check if this is a premium customer
    SELECT edition IN ('premium', 'trial') INTO is_premium
    FROM system_license
    WHERE active = 1
    LIMIT 1;

    -- Only prune if not premium customer
    IF NOT is_premium THEN
        -- Delete expired emails
        DELETE FROM email_quarantine
        WHERE quarantine_status = 'held'
          AND quarantine_expires_at < NOW();

        SET deleted_count = ROW_COUNT();

        -- Log the pruning action
        INSERT INTO quarantine_actions_log
            (quarantine_id, action_type, performed_by, user_role, action_details)
        SELECT
            0, 'expired', 'system', 'system',
            JSON_OBJECT('deleted_count', deleted_count, 'prune_date', NOW())
        FROM DUAL
        WHERE deleted_count > 0;

        SELECT CONCAT('Pruned ', deleted_count, ' expired emails') as result;
    ELSE
        SELECT 'Premium customer - skipping automatic pruning' as result;
    END IF;
END$$

DELIMITER ;


-- ============================================================================
-- VERIFY INSTALLATION
-- ============================================================================

SELECT 'Quarantine schema created successfully!' as Status;

SELECT
    COUNT(*) as table_count,
    'Tables created' as description
FROM information_schema.tables
WHERE table_schema = 'spacy_email_db'
  AND table_name IN (
    'email_quarantine',
    'quarantine_actions_log',
    'quarantine_statistics',
    'quarantine_config'
);

SELECT
    COUNT(*) as view_count,
    'Views created' as description
FROM information_schema.views
WHERE table_schema = 'spacy_email_db'
  AND table_name LIKE 'v_%quarantine%';

SELECT
    config_key,
    config_value,
    description
FROM quarantine_config
ORDER BY config_key;

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================
