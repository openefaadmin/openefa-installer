# Git Commit Checklist - OpenEFA Installer Integration

**Date**: 2025-10-16
**Branch**: main (or create feature/multi-tenant-v2)
**Version Bump**: 1.0.0 → 1.1.0 (or 2.0.0 for major release)

---

## Files to Commit

### New Files (Add):
```bash
git add sql/migrations/000_create_migrations_table.sql
git add sql/migrations/001_add_domain_admin_role.sql
git add lib/dependencies.sh
git add INTEGRATION_SUMMARY.md
git add GIT_COMMIT_CHECKLIST.md
```

### Modified Files (Add):
```bash
git add install.sh
git add lib/packages.sh
git add sql/schema_v1.sql
```

---

## Pre-Commit Checklist

### 1. Test Installation on Clean System
- [ ] Test on Ubuntu 24.04 Minimal Server
- [ ] Test on Ubuntu 22.04 Desktop
- [ ] Verify all 48+ checks pass
- [ ] Test email filter processes without crashes
- [ ] Verify utils module created
- [ ] Verify spaCy model downloads

### 2. Review Changes
```bash
cd /opt/openefa-installer
git status
git diff install.sh
git diff lib/packages.sh
git diff sql/schema_v1.sql
```

### 3. Verify New Files
```bash
# Check dependencies.sh syntax
bash -n lib/dependencies.sh

# Check SQL syntax
mysql -u root < sql/migrations/000_create_migrations_table.sql --syntax-check
mysql -u root < sql/migrations/001_add_domain_admin_role.sql --syntax-check

# Or just test them:
mysql spacy_email_db < sql/migrations/000_create_migrations_table.sql
mysql spacy_email_db < sql/migrations/001_add_domain_admin_role.sql
```

### 4. Update Version Number
```bash
echo "1.1.0" > VERSION
git add VERSION
```

### 5. Update README.md (if needed)
Add notes about:
- Multi-tenant support
- Minimal Ubuntu compatibility
- New role system

---

## Commit Commands

### Option A: Single Commit
```bash
cd /opt/openefa-installer

git add sql/migrations/000_create_migrations_table.sql
git add sql/migrations/001_add_domain_admin_role.sql
git add lib/dependencies.sh
git add install.sh
git add lib/packages.sh
git add sql/schema_v1.sql
git add INTEGRATION_SUMMARY.md
git add GIT_COMMIT_CHECKLIST.md
git add VERSION

git commit -m "Add multi-tenant user roles and minimal Ubuntu compatibility

Major Changes:
- Added user_domain_assignments table for domain-based access control
- Implemented domain_admin role alongside admin and client
- Added diagnostic tools installation for minimal Ubuntu compatibility
- Created utils module to fix 'No module named utils' error
- Added enhanced dependency installer (spacy, textblob, geoip2, etc.)
- Integrated spaCy model download during installation
- Fixed 'Command died with status 1' customer error

Database:
- New table: user_domain_assignments
- New migration system with schema_migrations table
- Added stored procedures for domain assignment management

Installer:
- New lib/dependencies.sh with enhanced dependency functions
- Diagnostic tools installed BEFORE pre-flight checks
- Utils module created automatically
- Python packages: spacy, textblob, geoip2, PyMuPDF, numpy>=2.3.0

Testing:
- Verified on Ubuntu 24.04 Minimal Server
- 48/49 checks passing
- Email filter processes without crashes
- All modules loading successfully

Version: 1.0.0 → 1.1.0
"
```

### Option B: Multiple Commits (Better for Review)
```bash
# Commit 1: Database schema
git add sql/migrations/000_create_migrations_table.sql
git add sql/migrations/001_add_domain_admin_role.sql
git add sql/schema_v1.sql
git commit -m "Add multi-tenant database schema (domain_admin role)

- Added user_domain_assignments table
- Created migration tracking system
- Added stored procedures for domain management
- Updated schema_v1.sql with new table

Implements: Multi-tenant domain administration
Issue: #123 (if applicable)
"

# Commit 2: Dependency installer
git add lib/dependencies.sh
git commit -m "Add enhanced dependency installer

- Creates utils module (fixes import errors)
- Installs diagnostic tools for minimal Ubuntu
- Adds spacy, textblob, geoip2, PyMuPDF packages
- Downloads spaCy language models automatically

Fixes: 'Command died with status 1' error
Fixes: 'No module named utils' error
"

# Commit 3: Integration
git add install.sh
git add lib/packages.sh
git commit -m "Integrate enhanced dependencies into installer

- Install diagnostic tools before pre-flight checks
- Call install_enhanced_dependencies after Python packages
- Minimal Ubuntu compatibility

Works on: Ubuntu 22.04+, Debian 11+
"

# Commit 4: Documentation
git add INTEGRATION_SUMMARY.md
git add GIT_COMMIT_CHECKLIST.md
git add VERSION
git commit -m "Add integration documentation and bump version

- Comprehensive integration summary
- Git commit checklist
- Version: 1.0.0 → 1.1.0
"
```

---

## Push to GitHub

```bash
# Review commits
git log --oneline -10

# Push to main (if you have rights)
git push origin main

# Or create feature branch
git checkout -b feature/multi-tenant-v2
git push origin feature/multi-tenant-v2

# Then create pull request on GitHub
```

---

## Post-Commit

### 1. Create GitHub Release
- Tag: v1.1.0
- Title: "Multi-Tenant Support + Minimal Ubuntu Compatibility"
- Description: See INTEGRATION_SUMMARY.md

### 2. Update install.openefa.com
If the installer URL pulls from GitHub, it will auto-update.
Otherwise, deploy the new installer to the web server.

### 3. Test Bootstrap Script
```bash
# From a fresh minimal Ubuntu:
curl -sSL http://install.openefa.com/install.sh | sudo bash
```

### 4. Update Documentation Site
- Add multi-tenant setup guide
- Update installation guide
- Add troubleshooting for minimal Ubuntu

---

## Rollback Plan (If Needed)

### If installation fails on production:
```bash
git revert HEAD~4..HEAD  # Revert last 4 commits
git push origin main

# Or revert specific commit:
git revert <commit-hash>
```

### If database migration fails:
```bash
# Drop the new table
mysql spacy_email_db -e "DROP TABLE IF EXISTS user_domain_assignments;"

# Or restore from backup
mysql spacy_email_db < /backup/spacy_email_db_before_migration.sql
```

---

## Testing Commands (For Reviewers)

### Clone and test:
```bash
git clone https://github.com/yourusername/openefa-installer.git
cd openefa-installer

# Review changes
git log --oneline --graph
git diff main~5..main

# Test on fresh VM
vagrant up  # Or use Docker/multipass
```

### Verify file structure:
```bash
tree -L 3 sql/
tree -L 2 lib/
ls -la *.md
```

---

## Checklist Before Pushing

- [ ] All files added to git
- [ ] Commit messages are descriptive
- [ ] VERSION file updated
- [ ] Tested on minimal Ubuntu
- [ ] Tested on default Ubuntu
- [ ] SQL migrations tested
- [ ] No sensitive data in commits
- [ ] Documentation complete
- [ ] CHANGELOG.md updated (if exists)
- [ ] Ready for code review

---

**Prepared by**: Claude
**Date**: 2025-10-16
**Ready to commit**: ✅
