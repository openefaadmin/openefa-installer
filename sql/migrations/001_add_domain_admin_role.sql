-- Migration: Add domain_admin role and user_domain_assignments table
-- Date: 2025-10-16
-- Purpose: Enable multi-tenant domain administration
--
-- This migration adds:
-- 1. user_domain_assignments table for mapping users to domains
-- 2. Support for domain_admin role in users table
-- 3. Indexes for performance

-- ============================================================================
-- 1. Create user_domain_assignments table
-- ============================================================================

CREATE TABLE IF NOT EXISTS `user_domain_assignments` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `user_id` INT(11) NOT NULL,
  `domain` VARCHAR(255) NOT NULL,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_by` INT(11) DEFAULT NULL COMMENT 'User ID who created this assignment',
  `is_active` TINYINT(1) DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_user_domain` (`user_id`, `domain`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_domain` (`domain`),
  KEY `idx_active` (`is_active`),
  CONSTRAINT `fk_user_domain_user`
    FOREIGN KEY (`user_id`)
    REFERENCES `users` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Maps users to domains they can manage (for domain_admin role)';

-- ============================================================================
-- 2. Update users table role column to support domain_admin
-- ============================================================================

-- Modify role column to include domain_admin as valid value
-- Note: This alters the ENUM if it exists, or sets default to support new role
ALTER TABLE `users`
  MODIFY COLUMN `role` VARCHAR(20) DEFAULT 'client'
  COMMENT 'User role: admin, domain_admin, or client';

-- ============================================================================
-- 3. Add helper views for common access patterns
-- ============================================================================

-- View: Users with their assigned domains
CREATE OR REPLACE VIEW `v_user_domains` AS
SELECT
  u.id AS user_id,
  u.email,
  u.role,
  u.first_name,
  u.last_name,
  uda.domain,
  uda.is_active AS domain_active,
  uda.created_at AS domain_assigned_at
FROM users u
LEFT JOIN user_domain_assignments uda ON u.id = uda.user_id
WHERE u.is_active = 1;

-- ============================================================================
-- 4. Create stored procedures for domain assignment management
-- ============================================================================

DELIMITER $$

-- Procedure: Assign domain to user
CREATE PROCEDURE IF NOT EXISTS `sp_assign_domain_to_user`(
  IN p_user_id INT,
  IN p_domain VARCHAR(255),
  IN p_created_by INT
)
BEGIN
  INSERT INTO user_domain_assignments (user_id, domain, created_by, is_active)
  VALUES (p_user_id, p_domain, p_created_by, 1)
  ON DUPLICATE KEY UPDATE
    is_active = 1,
    created_at = CURRENT_TIMESTAMP;
END$$

-- Procedure: Remove domain from user
CREATE PROCEDURE IF NOT EXISTS `sp_remove_domain_from_user`(
  IN p_user_id INT,
  IN p_domain VARCHAR(255)
)
BEGIN
  DELETE FROM user_domain_assignments
  WHERE user_id = p_user_id AND domain = p_domain;
END$$

-- Procedure: Get domains for user
CREATE PROCEDURE IF NOT EXISTS `sp_get_user_domains`(
  IN p_user_id INT
)
BEGIN
  SELECT domain
  FROM user_domain_assignments
  WHERE user_id = p_user_id AND is_active = 1
  ORDER BY domain;
END$$

DELIMITER ;

-- ============================================================================
-- 5. Create indexes for email_analysis table (if not exists)
-- ============================================================================

-- These indexes support domain-based filtering for domain_admin users
CREATE INDEX IF NOT EXISTS `idx_sender_domain`
  ON `email_analysis` (`sender_domain`);

CREATE INDEX IF NOT EXISTS `idx_recipient_domain`
  ON `email_analysis` (`recipient_domain`);

-- ============================================================================
-- 6. Migration complete
-- ============================================================================

-- Log migration completion
INSERT INTO schema_migrations (version, description, applied_at)
VALUES (
  '001',
  'Add domain_admin role and user_domain_assignments table',
  CURRENT_TIMESTAMP
) ON DUPLICATE KEY UPDATE applied_at = CURRENT_TIMESTAMP;
