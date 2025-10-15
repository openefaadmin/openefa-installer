-- OpenEFA ClamAV Integration - Database Schema Update
-- Version: 1.0.0
-- Date: 2025-10-14
-- Description: Adds virus detection tracking and quarantine support

-- Create virus_detections table for tracking all virus detections
CREATE TABLE IF NOT EXISTS virus_detections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    message_id VARCHAR(255),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    sender VARCHAR(255),
    recipient VARCHAR(255),
    sender_domain VARCHAR(255),
    virus_name VARCHAR(255),
    infected_file VARCHAR(255),
    file_size INT,
    action_taken ENUM('quarantined', 'rejected', 'tagged', 'passed') DEFAULT 'quarantined',
    client_domain_id INT,

    INDEX idx_timestamp (timestamp),
    INDEX idx_sender_domain (sender_domain),
    INDEX idx_virus_name (virus_name),
    INDEX idx_client_domain (client_domain_id),
    INDEX idx_message_id (message_id),

    FOREIGN KEY (client_domain_id) REFERENCES client_domains(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Update email_quarantine table to include virus information
ALTER TABLE email_quarantine
    ADD COLUMN IF NOT EXISTS virus_detected BOOLEAN DEFAULT FALSE AFTER phishing_detected,
    ADD COLUMN IF NOT EXISTS virus_name VARCHAR(255) AFTER virus_detected,
    ADD COLUMN IF NOT EXISTS virus_signature VARCHAR(255) AFTER virus_name,
    ADD COLUMN IF NOT EXISTS infected_attachments TEXT AFTER virus_signature;

-- Add index for quick virus detection queries
ALTER TABLE email_quarantine
    ADD INDEX IF NOT EXISTS idx_virus_detected (virus_detected);

-- Add comment for documentation
ALTER TABLE virus_detections COMMENT = 'Tracks all virus detections from ClamAV scanner';