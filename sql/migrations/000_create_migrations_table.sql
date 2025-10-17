-- Migration: Create schema_migrations tracking table
-- Date: 2025-10-16
-- Purpose: Track applied database migrations

CREATE TABLE IF NOT EXISTS `schema_migrations` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `version` VARCHAR(10) NOT NULL,
  `description` VARCHAR(255) NOT NULL,
  `applied_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_version` (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
COMMENT='Tracks which database migrations have been applied';

-- Insert initial migration record
INSERT IGNORE INTO schema_migrations (version, description, applied_at)
VALUES ('000', 'Create schema_migrations table', CURRENT_TIMESTAMP);
