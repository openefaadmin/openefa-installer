-- Notification tracking table
CREATE TABLE IF NOT EXISTS notification_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    notification_type VARCHAR(50) NOT NULL,
    recipient VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    email_id VARCHAR(255) NULL,
    trigger_reason VARCHAR(100) NULL,
    status ENUM('pending', 'sent', 'failed', 'rate_limited') DEFAULT 'pending',
    response_code VARCHAR(50) NULL,
    response_message TEXT NULL,
    sent_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_type (notification_type),
    INDEX idx_recipient (recipient),
    INDEX idx_status (status),
    INDEX idx_created (created_at),
    INDEX idx_email_id (email_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Notification rate limiting tracking
CREATE TABLE IF NOT EXISTS notification_rate_limit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    recipient VARCHAR(50) NOT NULL,
    notification_type VARCHAR(50) NOT NULL,
    last_sent TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    hourly_count INT DEFAULT 1,
    hour_window TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_recipient_type (recipient, notification_type),
    INDEX idx_hour_window (hour_window)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- System notification settings (stored in database for easy updates)
CREATE TABLE IF NOT EXISTS notification_settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT NOT NULL,
    description VARCHAR(255) NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
