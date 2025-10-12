# Database Migrations

This directory contains database migration scripts for upgrading OpenEFA between versions.

## Migration File Naming Convention

Migrations should be named: `v{old_version}_to_v{new_version}.sql`

Example: `v1.0.0_to_v1.1.0.sql`

## Migration Structure

Each migration file should:
1. Update the schema as needed (ADD/ALTER/DROP tables/columns)
2. Migrate existing data if necessary
3. Update the `schema_version` table

Example migration:

```sql
-- Migration from v1.0.0 to v1.1.0
-- Description: Add new feature X

-- Add new tables
CREATE TABLE IF NOT EXISTS new_feature (
  id INT AUTO_INCREMENT PRIMARY KEY,
  data VARCHAR(255)
);

-- Alter existing tables
ALTER TABLE existing_table ADD COLUMN new_field VARCHAR(100);

-- Update schema version
INSERT INTO schema_version (version, description)
VALUES ('1.1.0', 'Added feature X');
```

## How Migrations Are Applied

The installer automatically detects existing installations and applies migrations:

1. Checks current version from `schema_version` table
2. Finds all migrations newer than current version
3. Applies them in order
4. Updates `schema_version` table after each migration

## Testing Migrations

Always test migrations on a backup/snapshot before applying to production:

1. Create database backup
2. Apply migration
3. Verify schema and data integrity
4. Test application functionality
5. Document any manual steps required
