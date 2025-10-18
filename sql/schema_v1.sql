/*M!999999\- enable the sandbox mode */ 

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) DEFAULT NULL,
  `action` varchar(100) NOT NULL,
  `details` text DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_audit_log_user_id` (`user_id`),
  KEY `idx_audit_log_created_at` (`created_at`),
  CONSTRAINT `audit_log_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=619 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `behavioral_anomalies` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sender_email` varchar(255) NOT NULL,
  `recipient_email` varchar(255) DEFAULT NULL,
  `message_id` varchar(255) DEFAULT NULL,
  `anomaly_timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `anomaly_type` enum('time','volume','recipient','content','location','pattern') NOT NULL,
  `anomaly_severity` enum('low','medium','high','critical') NOT NULL,
  `anomaly_score` float DEFAULT 0,
  `expected_value` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'What was expected based on baseline' CHECK (json_valid(`expected_value`)),
  `actual_value` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'What actually occurred' CHECK (json_valid(`actual_value`)),
  `deviation_percentage` float DEFAULT NULL,
  `description` text DEFAULT NULL,
  `was_blocked` tinyint(1) DEFAULT 0,
  `was_false_positive` tinyint(1) DEFAULT 0,
  `action_taken` enum('none','logged','flagged','quarantined','blocked') DEFAULT 'logged',
  `admin_reviewed` tinyint(1) DEFAULT 0,
  `admin_notes` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_sender` (`sender_email`),
  KEY `idx_timestamp` (`anomaly_timestamp`),
  KEY `idx_severity` (`anomaly_severity`),
  KEY `idx_type` (`anomaly_type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `behavioral_config` (
  `config_key` varchar(100) NOT NULL,
  `config_value` varchar(255) DEFAULT NULL,
  `description` text DEFAULT NULL,
  PRIMARY KEY (`config_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `behavioral_config`
--

INSERT INTO `behavioral_config` (`config_key`, `config_value`, `description`) VALUES
('min_emails_for_baseline', '20', 'Minimum number of emails required to establish a behavioral baseline'),
('volume_spike_threshold', '3.0', 'Multiplier for detecting unusual email volume (3.0 = 3x normal rate)'),
('new_recipient_threshold', '0.5', 'Threshold for flagging unusual new recipient patterns (0.5 = 50% new)'),
('time_anomaly_hours', '3', 'Hours outside normal sending pattern to trigger time anomaly'),
('anomaly_score_threshold', '7.0', 'Score threshold for flagging behavioral anomalies'),
('auto_quarantine_score', '9.0', 'Score threshold for automatic quarantine of suspicious emails');

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `blocked_attempts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_domain_id` int(11) NOT NULL,
  `timestamp` datetime DEFAULT NULL,
  `sender_address` varchar(255) DEFAULT NULL,
  `sender_domain` varchar(255) DEFAULT NULL,
  `sender_ip` varchar(45) DEFAULT NULL,
  `sender_country` varchar(2) DEFAULT NULL,
  `rule_matched` varchar(255) DEFAULT NULL,
  `rule_type` varchar(50) DEFAULT NULL,
  `smtp_session_id` varchar(100) DEFAULT NULL,
  `message_id` varchar(255) DEFAULT NULL,
  `subject` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_blocked_attempts_timestamp` (`timestamp`),
  KEY `idx_blocked_attempts_sender` (`sender_domain`,`timestamp`),
  KEY `ix_blocked_attempts_sender_domain` (`sender_domain`),
  KEY `idx_blocked_attempts_reporting` (`client_domain_id`,`timestamp`),
  CONSTRAINT `blocked_attempts_ibfk_1` FOREIGN KEY (`client_domain_id`) REFERENCES `client_domains` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5753 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `blocking_rules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_domain_id` int(11) NOT NULL,
  `rule_type` varchar(50) NOT NULL,
  `rule_value` varchar(255) NOT NULL,
  `rule_pattern` varchar(50) DEFAULT NULL,
  `recipient_pattern` varchar(255) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `created_at` datetime DEFAULT NULL,
  `created_by` varchar(100) DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  `priority` int(11) DEFAULT NULL,
  `whitelist` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_blocking_rules_lookup` (`client_domain_id`,`rule_type`,`active`),
  KEY `idx_blocking_rules_priority` (`priority`),
  CONSTRAINT `blocking_rules_ibfk_1` FOREIGN KEY (`client_domain_id`) REFERENCES `client_domains` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=71 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_domains` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `domain` varchar(255) NOT NULL,
  `client_name` varchar(255) DEFAULT NULL,
  `relay_host` varchar(255) DEFAULT NULL,
  `relay_port` int(11) DEFAULT 25,
  `created_at` datetime DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  `active` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_client_domains_domain` (`domain`)
) ENGINE=InnoDB AUTO_INCREMENT=29 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `client_modules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_domain` varchar(255) NOT NULL,
  `module_name` varchar(100) NOT NULL,
  `enabled` tinyint(1) DEFAULT 0,
  `subscription_start` date DEFAULT NULL,
  `subscription_end` date DEFAULT NULL,
  `config` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`config`)),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_client_module` (`client_domain`,`module_name`),
  KEY `idx_client_domain` (`client_domain`),
  KEY `idx_module_enabled` (`module_name`,`enabled`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `processed_domains` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `domain` varchar(255) NOT NULL,
  `email_count` int(11) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_seen` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `domain` (`domain`),
  KEY `idx_domain` (`domain`),
  KEY `idx_last_seen` (`last_seen`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `compliance_entities` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email_id` int(11) DEFAULT NULL,
  `client_domain` varchar(255) DEFAULT NULL,
  `entity_type` varchar(50) DEFAULT NULL,
  `entity_value` text DEFAULT NULL,
  `entity_context` text DEFAULT NULL,
  `confidence_score` float DEFAULT NULL,
  `extracted_date` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_email_entities` (`email_id`),
  KEY `idx_client_entities` (`client_domain`,`entity_type`),
  CONSTRAINT `compliance_entities_ibfk_1` FOREIGN KEY (`email_id`) REFERENCES `email_analysis` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=14745 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `compromise_indicators` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sender_email` varchar(255) NOT NULL,
  `indicator_timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  `sudden_volume_spike` tinyint(1) DEFAULT 0,
  `unusual_send_time` tinyint(1) DEFAULT 0,
  `new_recipient_pattern` tinyint(1) DEFAULT 0,
  `suspicious_content_change` tinyint(1) DEFAULT 0,
  `geographic_anomaly` tinyint(1) DEFAULT 0,
  `authentication_downgrade` tinyint(1) DEFAULT 0,
  `total_indicators` int(11) DEFAULT 0,
  `risk_score` float DEFAULT 0,
  `details` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`details`)),
  `requires_review` tinyint(1) DEFAULT 1,
  PRIMARY KEY (`id`),
  KEY `idx_sender` (`sender_email`),
  KEY `idx_timestamp` (`indicator_timestamp`),
  KEY `idx_risk` (`risk_score`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `conversation_domain_stats` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `domain` varchar(255) NOT NULL,
  `total_messages` int(11) DEFAULT 0,
  `avg_message_length` int(11) DEFAULT 0,
  `avg_spam_score` float DEFAULT 0,
  `common_topics` text DEFAULT NULL,
  `last_updated` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `domain` (`domain`),
  KEY `idx_domain` (`domain`),
  KEY `idx_total_messages` (`total_messages`)
) ENGINE=InnoDB AUTO_INCREMENT=7747 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `conversation_learning_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `config_key` varchar(50) NOT NULL,
  `config_value` varchar(255) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `config_key` (`config_key`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `conversation_learning_config`
--

INSERT INTO `conversation_learning_config` (`config_key`, `config_value`, `description`) VALUES
('max_adjustment', '2.0', 'Maximum spam score adjustment for legitimate conversation patterns'),
('learning_enabled', 'true', 'Enable/disable conversation pattern learning'),
('min_messages_for_learning', '10', 'Minimum messages required before applying learning adjustments'),
('vocab_learning_threshold', '3', 'Minimum frequency before adding vocabulary to learning database'),
('relationship_confidence_threshold', '5', 'Minimum message count for high confidence relationships'),
('auto_cleanup_days', '365', 'Days to retain old conversation learning data');

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `conversation_learning_progress` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date` date NOT NULL,
  `patterns_learned` int(11) DEFAULT 0,
  `relationships_formed` int(11) DEFAULT 0,
  `phrases_identified` int(11) DEFAULT 0,
  `emails_processed` int(11) DEFAULT 0,
  `avg_confidence` float DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `date` (`date`),
  KEY `idx_date` (`date`)
) ENGINE=InnoDB AUTO_INCREMENT=7715 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `conversation_learning_stats` AS SELECT
 1 AS `vocabulary_count`,
  1 AS `relationship_count`,
  1 AS `phrase_count`,
  1 AS `domain_count`,
  1 AS `new_patterns_24h`,
  1 AS `new_patterns_7d`,
  1 AS `avg_legitimate_score` */;
SET character_set_client = @saved_cs_client;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `conversation_phrases` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `phrase` varchar(100) NOT NULL,
  `frequency` int(11) DEFAULT 1,
  `avg_spam_score` float DEFAULT 0,
  `last_seen` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `phrase` (`phrase`),
  KEY `idx_frequency` (`frequency`),
  KEY `idx_phrase` (`phrase`)
) ENGINE=InnoDB AUTO_INCREMENT=5361 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `conversation_relationships` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sender_domain` varchar(255) NOT NULL,
  `recipient_domain` varchar(255) NOT NULL,
  `message_count` int(11) DEFAULT 1,
  `avg_spam_score` float DEFAULT 0,
  `last_communication` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_relationship` (`sender_domain`,`recipient_domain`),
  KEY `idx_message_count` (`message_count`),
  KEY `idx_domains` (`sender_domain`,`recipient_domain`)
) ENGINE=InnoDB AUTO_INCREMENT=9851 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `conversation_vocabulary` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `word_hash` varchar(32) NOT NULL,
  `frequency` int(11) DEFAULT 1,
  `last_seen` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `word_hash` (`word_hash`),
  KEY `idx_frequency` (`frequency`),
  KEY `idx_last_seen` (`last_seen`)
) ENGINE=InnoDB AUTO_INCREMENT=258217 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `current_effectiveness` AS SELECT
 1 AS `id`,
  1 AS `metric_date`,
  1 AS `total_emails`,
  1 AS `spam_caught`,
  1 AS `clean_passed`,
  1 AS `gray_area`,
  1 AS `false_positives`,
  1 AS `false_negatives`,
  1 AS `avg_spam_score`,
  1 AS `detection_rate`,
  1 AS `false_positive_rate`,
  1 AS `true_positive_rate`,
  1 AS `precision_score`,
  1 AS `recall_score`,
  1 AS `f1_score`,
  1 AS `effectiveness_score`,
  1 AS `auto_whitelists_added`,
  1 AS `unique_senders_released`,
  1 AS `learning_rate`,
  1 AS `created_at`,
  1 AS `performance_rating`,
  1 AS `accuracy_percentage` */;
SET character_set_client = @saved_cs_client;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `effectiveness_metrics` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `metric_date` date NOT NULL,
  `total_emails` int(11) DEFAULT 0,
  `spam_caught` int(11) DEFAULT 0,
  `clean_passed` int(11) DEFAULT 0,
  `gray_area` int(11) DEFAULT 0,
  `false_positives` int(11) DEFAULT 0,
  `false_negatives` int(11) DEFAULT 0,
  `avg_spam_score` float DEFAULT 0,
  `detection_rate` float DEFAULT 0,
  `false_positive_rate` float DEFAULT 0,
  `true_positive_rate` float DEFAULT 0,
  `precision_score` float DEFAULT 0,
  `recall_score` float DEFAULT 0,
  `f1_score` float DEFAULT 0,
  `effectiveness_score` float DEFAULT 0,
  `auto_whitelists_added` int(11) DEFAULT 0,
  `unique_senders_released` int(11) DEFAULT 0,
  `learning_rate` float DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `metric_date` (`metric_date`),
  KEY `idx_metric_date` (`metric_date`),
  KEY `idx_effectiveness` (`effectiveness_score`)
) ENGINE=InnoDB AUTO_INCREMENT=49 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `effectiveness_trends` AS SELECT
 1 AS `metric_date`,
  1 AS `effectiveness_score`,
  1 AS `false_positive_rate`,
  1 AS `detection_rate`,
  1 AS `learning_rate`,
  1 AS `week_avg`,
  1 AS `month_avg` */;
SET character_set_client = @saved_cs_client;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `effectiveness_weekly_summary` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `week_start` date NOT NULL,
  `week_end` date NOT NULL,
  `avg_effectiveness` float DEFAULT 0,
  `total_emails` int(11) DEFAULT 0,
  `total_spam_caught` int(11) DEFAULT 0,
  `total_false_positives` int(11) DEFAULT 0,
  `improvement_from_previous` float DEFAULT NULL,
  `best_day_effectiveness` float DEFAULT 0,
  `worst_day_effectiveness` float DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `week_start` (`week_start`),
  KEY `idx_week` (`week_start`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `email_analysis` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message_id` varchar(255) DEFAULT NULL,
  `timestamp` datetime DEFAULT NULL,
  `sender` varchar(255) DEFAULT NULL,
  `recipients` text DEFAULT NULL,
  `subject` text DEFAULT NULL,
  `spam_score` float DEFAULT NULL,
  `entities` text DEFAULT NULL,
  `all_links_count` int(11) DEFAULT NULL,
  `suspicious_links` text DEFAULT NULL,
  `model_name` varchar(50) DEFAULT NULL,
  `raw_text_length` int(11) DEFAULT NULL,
  `urgency_score` float DEFAULT NULL,
  `entity_combos` text DEFAULT NULL,
  `sentiment_score` float DEFAULT NULL,
  `email_category` varchar(50) DEFAULT NULL,
  `email_topics` text DEFAULT NULL,
  `content_summary` text DEFAULT NULL,
  `detected_language` varchar(10) DEFAULT NULL,
  `language_confidence` float DEFAULT NULL,
  `sentiment_polarity` float DEFAULT NULL,
  `sentiment_subjectivity` float DEFAULT NULL,
  `sentiment_extremity` float DEFAULT NULL,
  `sentiment_manipulation` float DEFAULT NULL,
  `manipulation_indicators` text DEFAULT NULL,
  `category_confidence` float DEFAULT NULL,
  `secondary_categories` text DEFAULT NULL,
  `classification_scores` text DEFAULT NULL,
  `has_attachments` int(11) DEFAULT NULL,
  `text_formatting_score` float DEFAULT NULL,
  `sender_reputation` float DEFAULT NULL,
  `training_data_saved` int(11) DEFAULT NULL,
  `spoofing_score` float DEFAULT 0,
  `spoofed_domains` text DEFAULT NULL,
  `spoofing_risk_level` varchar(10) DEFAULT NULL,
  `spoofing_patterns` text DEFAULT NULL,
  `is_government` tinyint(1) DEFAULT 0,
  `government_confidence` float DEFAULT 0,
  `government_method` text DEFAULT NULL,
  `original_spf` varchar(20) DEFAULT NULL,
  `original_dkim` varchar(20) DEFAULT NULL,
  `original_dmarc` varchar(20) DEFAULT NULL,
  `original_sender_ip` varchar(45) DEFAULT NULL,
  `pii_detected` tinyint(1) DEFAULT 0,
  `pii_types` text DEFAULT NULL,
  `raw_email` longtext DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=149491 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `email_threads` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `thread_id` varchar(32) NOT NULL,
  `participants` text DEFAULT NULL,
  `first_seen` datetime DEFAULT NULL,
  `last_seen` datetime DEFAULT NULL,
  `message_count` int(11) DEFAULT NULL,
  `trust_score` float DEFAULT NULL,
  `business_indicators` text DEFAULT NULL,
  `authentication_history` text DEFAULT NULL,
  `subject_pattern` varchar(255) DEFAULT NULL,
  `domain_reputation` float DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ix_email_threads_thread_id` (`thread_id`)
) ENGINE=InnoDB AUTO_INCREMENT=28780 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `emails` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message_id` varchar(255) NOT NULL,
  `sender` varchar(255) DEFAULT NULL,
  `recipients` text DEFAULT NULL,
  `subject` varchar(500) DEFAULT NULL,
  `body` text DEFAULT NULL,
  `raw_email` longtext DEFAULT NULL,
  `received_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `processed` tinyint(1) DEFAULT 0,
  `spam_score` float DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `message_id` (`message_id`),
  KEY `idx_message_id` (`message_id`),
  KEY `idx_sender` (`sender`),
  KEY `idx_received_at` (`received_at`),
  KEY `idx_processed` (`processed`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `false_positive_tracking` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message_id` varchar(255) DEFAULT NULL,
  `sender_email` varchar(255) DEFAULT NULL,
  `recipient_email` varchar(255) DEFAULT NULL,
  `original_spam_score` float DEFAULT NULL,
  `release_timestamp` datetime DEFAULT NULL,
  `release_count` int(11) DEFAULT 1,
  `auto_whitelisted` tinyint(1) DEFAULT 0,
  `domain` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_sender` (`sender_email`),
  KEY `idx_domain` (`domain`),
  KEY `idx_release_date` (`release_timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `hosted_domains` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `domain` varchar(100) NOT NULL,
  `company_name` varchar(200) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `domain` (`domain`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `module_alerts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_domain` varchar(255) NOT NULL,
  `alert_type` varchar(100) NOT NULL,
  `alert_name` varchar(255) DEFAULT NULL,
  `entity_pattern` varchar(500) DEFAULT NULL,
  `entity_type` varchar(50) DEFAULT NULL,
  `keywords` text DEFAULT NULL,
  `notification_emails` text DEFAULT NULL,
  `webhook_url` varchar(500) DEFAULT NULL,
  `active` tinyint(1) DEFAULT 1,
  `priority` enum('low','medium','high','critical') DEFAULT 'medium',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_client_alerts` (`client_domain`,`active`),
  KEY `idx_alert_type` (`alert_type`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `module_effectiveness` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `module_name` varchar(100) NOT NULL,
  `metric_date` date NOT NULL,
  `triggers` int(11) DEFAULT 0,
  `true_positives` int(11) DEFAULT 0,
  `false_positives` int(11) DEFAULT 0,
  `accuracy` float DEFAULT 0,
  `avg_score_contribution` float DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_module_date` (`module_name`,`metric_date`),
  KEY `idx_module` (`module_name`),
  KEY `idx_date` (`metric_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `module_usage_stats` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_domain` varchar(255) NOT NULL,
  `module_name` varchar(100) NOT NULL,
  `usage_date` date NOT NULL,
  `usage_count` int(11) DEFAULT 0,
  `entities_extracted` int(11) DEFAULT 0,
  `alerts_triggered` int(11) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_usage_day` (`client_domain`,`module_name`,`usage_date`),
  KEY `idx_usage_date` (`client_domain`,`usage_date`)
) ENGINE=InnoDB AUTO_INCREMENT=24403 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `ner_entities` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `entity_text` varchar(255) NOT NULL,
  `entity_type` varchar(50) NOT NULL,
  `message_id` varchar(255) DEFAULT NULL,
  `sender` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `confidence` float DEFAULT NULL,
  `context` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_entity_text` (`entity_text`),
  KEY `idx_entity_type` (`entity_type`),
  KEY `idx_message_id` (`message_id`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `password_reset_tokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `token` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `used` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `token` (`token`),
  KEY `user_id` (`user_id`),
  KEY `idx_reset_tokens_token` (`token`),
  CONSTRAINT `password_reset_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `quarantine_releases` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message_id` varchar(100) DEFAULT NULL,
  `sender` varchar(255) DEFAULT NULL,
  `recipient` varchar(255) DEFAULT NULL,
  `subject` varchar(500) DEFAULT NULL,
  `original_spam_score` float DEFAULT NULL,
  `release_time` datetime DEFAULT NULL,
  `release_user` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_sender` (`sender`),
  KEY `idx_time` (`release_time`)
) ENGINE=InnoDB AUTO_INCREMENT=1367 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
SET @saved_cs_client     = @@character_set_client;
SET character_set_client = utf8mb4;
/*!50001 CREATE VIEW `sender_anomaly_status` AS SELECT
 1 AS `sender_email`,
  1 AS `sender_domain`,
  1 AS `total_emails_analyzed`,
  1 AS `learning_confidence`,
  1 AS `anomaly_count`,
  1 AS `last_anomaly_date`,
  1 AS `recent_anomalies_7d`,
  1 AS `highest_severity_7d`,
  1 AS `baseline_status` */;
SET character_set_client = @saved_cs_client;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sender_behavior_baseline` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sender_email` varchar(255) NOT NULL,
  `sender_domain` varchar(255) NOT NULL,
  `typical_send_hours` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Array of hours [0-23] when typically sends' CHECK (json_valid(`typical_send_hours`)),
  `typical_send_days` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Array of days [0-6] when typically sends' CHECK (json_valid(`typical_send_days`)),
  `timezone_estimate` varchar(50) DEFAULT NULL,
  `avg_daily_volume` float DEFAULT 0,
  `max_daily_volume` int(11) DEFAULT 0,
  `avg_recipients_per_email` float DEFAULT 0,
  `max_recipients_per_email` int(11) DEFAULT 0,
  `typical_recipient_domains` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Top recipient domains with percentages' CHECK (json_valid(`typical_recipient_domains`)),
  `internal_vs_external_ratio` float DEFAULT 0.5,
  `new_recipient_frequency` float DEFAULT 0 COMMENT 'How often sends to new recipients',
  `avg_email_length` int(11) DEFAULT 0,
  `typical_attachment_types` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Common attachment extensions' CHECK (json_valid(`typical_attachment_types`)),
  `uses_html_frequency` float DEFAULT 0,
  `typical_subject_patterns` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Common subject keywords' CHECK (json_valid(`typical_subject_patterns`)),
  `consistency_score` float DEFAULT 0 COMMENT 'How consistent the behavior is',
  `last_anomaly_date` timestamp NULL DEFAULT NULL,
  `anomaly_count` int(11) DEFAULT 0,
  `total_emails_analyzed` int(11) DEFAULT 0,
  `learning_confidence` float DEFAULT 0,
  `last_updated` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_sender` (`sender_email`),
  KEY `idx_domain` (`sender_domain`),
  KEY `idx_confidence` (`learning_confidence`)
) ENGINE=InnoDB AUTO_INCREMENT=1925 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sending_patterns` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sender_email` varchar(255) NOT NULL,
  `pattern_date` date NOT NULL,
  `hour_0` int(11) DEFAULT 0,
  `hour_1` int(11) DEFAULT 0,
  `hour_2` int(11) DEFAULT 0,
  `hour_3` int(11) DEFAULT 0,
  `hour_4` int(11) DEFAULT 0,
  `hour_5` int(11) DEFAULT 0,
  `hour_6` int(11) DEFAULT 0,
  `hour_7` int(11) DEFAULT 0,
  `hour_8` int(11) DEFAULT 0,
  `hour_9` int(11) DEFAULT 0,
  `hour_10` int(11) DEFAULT 0,
  `hour_11` int(11) DEFAULT 0,
  `hour_12` int(11) DEFAULT 0,
  `hour_13` int(11) DEFAULT 0,
  `hour_14` int(11) DEFAULT 0,
  `hour_15` int(11) DEFAULT 0,
  `hour_16` int(11) DEFAULT 0,
  `hour_17` int(11) DEFAULT 0,
  `hour_18` int(11) DEFAULT 0,
  `hour_19` int(11) DEFAULT 0,
  `hour_20` int(11) DEFAULT 0,
  `hour_21` int(11) DEFAULT 0,
  `hour_22` int(11) DEFAULT 0,
  `hour_23` int(11) DEFAULT 0,
  `total_day` int(11) DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_sender_date` (`sender_email`,`pattern_date`),
  KEY `idx_date` (`pattern_date`)
) ENGINE=InnoDB AUTO_INCREMENT=3243 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `spacy_analysis` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `timestamp` datetime DEFAULT NULL,
  `message_id` varchar(255) NOT NULL,
  `sender` varchar(255) DEFAULT NULL,
  `recipients` text DEFAULT NULL,
  `subject` varchar(500) DEFAULT NULL,
  `spam_score` float DEFAULT NULL,
  `entities` text DEFAULT NULL,
  `all_links_count` int(11) DEFAULT NULL,
  `suspicious_links` text DEFAULT NULL,
  `model_name` varchar(100) DEFAULT NULL,
  `raw_text_length` int(11) DEFAULT NULL,
  `urgency_score` float DEFAULT NULL,
  `entity_combos` text DEFAULT NULL,
  `sentiment_score` float DEFAULT NULL,
  `email_category` varchar(100) DEFAULT NULL,
  `email_topics` text DEFAULT NULL,
  `content_summary` text DEFAULT NULL,
  `detected_language` varchar(10) DEFAULT NULL,
  `language_confidence` float DEFAULT NULL,
  `sentiment_polarity` float DEFAULT NULL,
  `sentiment_subjectivity` float DEFAULT NULL,
  `sentiment_extremity` float DEFAULT NULL,
  `sentiment_manipulation` float DEFAULT NULL,
  `manipulation_indicators` text DEFAULT NULL,
  `category_confidence` float DEFAULT NULL,
  `secondary_categories` text DEFAULT NULL,
  `classification_scores` text DEFAULT NULL,
  `has_attachments` tinyint(1) DEFAULT NULL,
  `training_data_saved` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=72 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `thread_messages` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `thread_id` varchar(32) DEFAULT NULL,
  `message_id` varchar(255) DEFAULT NULL,
  `sender` varchar(255) DEFAULT NULL,
  `timestamp` datetime DEFAULT NULL,
  `authentication_status` varchar(255) DEFAULT NULL,
  `content_hash` varchar(32) DEFAULT NULL,
  `business_score` float DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_thread_messages_thread_id` (`thread_id`),
  KEY `ix_thread_messages_timestamp` (`timestamp`),
  KEY `idx_thread_messages_sender` (`sender`),
  CONSTRAINT `thread_messages_ibfk_1` FOREIGN KEY (`thread_id`) REFERENCES `email_threads` (`thread_id`)
) ENGINE=InnoDB AUTO_INCREMENT=89548 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `true_positive_validation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message_id` varchar(255) DEFAULT NULL,
  `sender_email` varchar(255) DEFAULT NULL,
  `spam_score` float DEFAULT NULL,
  `detection_method` varchar(100) DEFAULT NULL,
  `validation_source` varchar(50) DEFAULT 'automatic',
  `validation_timestamp` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_validation_date` (`validation_timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `trusted_senders` (
  `sender_email` varchar(255) NOT NULL,
  `trust_score` int(11) DEFAULT 5,
  `release_count` int(11) DEFAULT 1,
  `first_seen` datetime DEFAULT NULL,
  `last_released` datetime DEFAULT NULL,
  `last_subject` varchar(500) DEFAULT NULL,
  PRIMARY KEY (`sender_email`),
  KEY `idx_trust` (`trust_score`),
  KEY `idx_releases` (`release_count`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_sessions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `session_token` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `expires_at` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `is_active` tinyint(1) DEFAULT 1,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `session_token` (`session_token`),
  KEY `idx_sessions_user_id` (`user_id`),
  KEY `idx_sessions_token` (`session_token`),
  CONSTRAINT `user_sessions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `domain` varchar(100) NOT NULL,
  `authorized_domains` text DEFAULT NULL,
  `role` varchar(20) DEFAULT 'client',
  `first_name` varchar(100) DEFAULT NULL,
  `last_name` varchar(100) DEFAULT NULL,
  `company_name` varchar(200) DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `email_verified` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_login` timestamp NULL DEFAULT NULL,
  `failed_login_attempts` int(11) DEFAULT 0,
  `locked_until` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  KEY `idx_users_email` (`email`),
  KEY `idx_users_domain` (`domain`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_domain_assignments`
-- Multi-tenant domain assignment for domain_admin users
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_domain_assignments` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `domain` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `created_by` int(11) DEFAULT NULL COMMENT 'User ID who created this assignment',
  `is_active` tinyint(1) DEFAULT 1,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_user_domain` (`user_id`,`domain`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_domain` (`domain`),
  KEY `idx_active` (`is_active`),
  CONSTRAINT `fk_user_domain_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Maps users to domains they can manage (for domain_admin role)';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `whitelist_requests`
--

/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `whitelist_requests` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sender_email` varchar(255) DEFAULT NULL,
  `recipient_email` varchar(255) DEFAULT NULL,
  `requested_by` varchar(255) DEFAULT NULL,
  `message_id` varchar(100) DEFAULT NULL,
  `subject` varchar(500) DEFAULT NULL,
  `reason` varchar(500) DEFAULT NULL,
  `request_time` datetime DEFAULT NULL,
  `status` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_sender` (`sender_email`),
  KEY `idx_recipient` (`recipient_email`),
  KEY `idx_time` (`request_time`)
) ENGINE=InnoDB AUTO_INCREMENT=71 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!50001 DROP VIEW IF EXISTS `conversation_learning_stats`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb3 */;
/*!50001 SET character_set_results     = utf8mb3 */;
/*!50001 SET collation_connection      = utf8mb3_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`spacy_user`@`localhost` SQL SECURITY DEFINER */
/*!50001 VIEW `conversation_learning_stats` AS select (select count(0) from `conversation_vocabulary` where `conversation_vocabulary`.`frequency` > 1) AS `vocabulary_count`,(select count(0) from `conversation_relationships`) AS `relationship_count`,(select count(0) from `conversation_phrases`) AS `phrase_count`,(select count(distinct `conversation_domain_stats`.`domain`) from `conversation_domain_stats`) AS `domain_count`,(select count(0) from `conversation_vocabulary` where `conversation_vocabulary`.`last_seen` > current_timestamp() - interval 1 day) AS `new_patterns_24h`,(select count(0) from `conversation_vocabulary` where `conversation_vocabulary`.`last_seen` > current_timestamp() - interval 7 day) AS `new_patterns_7d`,(select avg(`conversation_relationships`.`avg_spam_score`) from `conversation_relationships` where `conversation_relationships`.`message_count` > 3) AS `avg_legitimate_score` */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;
/*!50001 DROP VIEW IF EXISTS `current_effectiveness`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb3 */;
/*!50001 SET character_set_results     = utf8mb3 */;
/*!50001 SET collation_connection      = utf8mb3_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`spacy_user`@`localhost` SQL SECURITY DEFINER */
/*!50001 VIEW `current_effectiveness` AS select `em`.`id` AS `id`,`em`.`metric_date` AS `metric_date`,`em`.`total_emails` AS `total_emails`,`em`.`spam_caught` AS `spam_caught`,`em`.`clean_passed` AS `clean_passed`,`em`.`gray_area` AS `gray_area`,`em`.`false_positives` AS `false_positives`,`em`.`false_negatives` AS `false_negatives`,`em`.`avg_spam_score` AS `avg_spam_score`,`em`.`detection_rate` AS `detection_rate`,`em`.`false_positive_rate` AS `false_positive_rate`,`em`.`true_positive_rate` AS `true_positive_rate`,`em`.`precision_score` AS `precision_score`,`em`.`recall_score` AS `recall_score`,`em`.`f1_score` AS `f1_score`,`em`.`effectiveness_score` AS `effectiveness_score`,`em`.`auto_whitelists_added` AS `auto_whitelists_added`,`em`.`unique_senders_released` AS `unique_senders_released`,`em`.`learning_rate` AS `learning_rate`,`em`.`created_at` AS `created_at`,case when `em`.`effectiveness_score` >= 95 then 'Excellent' when `em`.`effectiveness_score` >= 90 then 'Good' when `em`.`effectiveness_score` >= 85 then 'Acceptable' else 'Needs Improvement' end AS `performance_rating`,round(100 - `em`.`false_positive_rate` * 100,2) AS `accuracy_percentage` from `effectiveness_metrics` `em` where `em`.`metric_date` = curdate() */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;
/*!50001 DROP VIEW IF EXISTS `effectiveness_trends`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb3 */;
/*!50001 SET character_set_results     = utf8mb3 */;
/*!50001 SET collation_connection      = utf8mb3_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`spacy_user`@`localhost` SQL SECURITY DEFINER */
/*!50001 VIEW `effectiveness_trends` AS select `effectiveness_metrics`.`metric_date` AS `metric_date`,`effectiveness_metrics`.`effectiveness_score` AS `effectiveness_score`,`effectiveness_metrics`.`false_positive_rate` AS `false_positive_rate`,`effectiveness_metrics`.`detection_rate` AS `detection_rate`,`effectiveness_metrics`.`learning_rate` AS `learning_rate`,avg(`effectiveness_metrics`.`effectiveness_score`) over ( order by `effectiveness_metrics`.`metric_date` rows between 6 preceding  and  current row ) AS `week_avg`,avg(`effectiveness_metrics`.`effectiveness_score`) over ( order by `effectiveness_metrics`.`metric_date` rows between 29 preceding  and  current row ) AS `month_avg` from `effectiveness_metrics` where `effectiveness_metrics`.`metric_date` >= curdate() - interval 30 day order by `effectiveness_metrics`.`metric_date` desc */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;
/*!50001 DROP VIEW IF EXISTS `sender_anomaly_status`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb3 */;
/*!50001 SET character_set_results     = utf8mb3 */;
/*!50001 SET collation_connection      = utf8mb3_general_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`root`@`localhost` SQL SECURITY DEFINER */
/*!50001 VIEW `sender_anomaly_status` AS select `sbb`.`sender_email` AS `sender_email`,`sbb`.`sender_domain` AS `sender_domain`,`sbb`.`total_emails_analyzed` AS `total_emails_analyzed`,`sbb`.`learning_confidence` AS `learning_confidence`,`sbb`.`anomaly_count` AS `anomaly_count`,`sbb`.`last_anomaly_date` AS `last_anomaly_date`,count(distinct `ba`.`id`) AS `recent_anomalies_7d`,max(`ba`.`anomaly_severity`) AS `highest_severity_7d`,case when `sbb`.`learning_confidence` >= 0.8 then 'Established' when `sbb`.`learning_confidence` >= 0.5 then 'Learning' else 'Insufficient Data' end AS `baseline_status` from (`sender_behavior_baseline` `sbb` left join `behavioral_anomalies` `ba` on(`sbb`.`sender_email` = `ba`.`sender_email` and `ba`.`anomaly_timestamp` >= current_timestamp() - interval 7 day)) group by `sbb`.`sender_email` */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

