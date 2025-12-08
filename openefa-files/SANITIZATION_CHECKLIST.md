# Manual Sanitization Checklist

Before releasing these files publicly, manually review:

## Critical Items

### web/app.py
- [ ] Replace HOSTED_DOMAINS hardcoded list with database query:
```python
# OLD (line ~53):
HOSTED_DOMAINS = ['example.com', 'client1.com', ...]

# NEW:
def get_hosted_domains():
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT domain FROM client_domains WHERE is_active = 1")
    return [row['domain'] for row in cursor.fetchall()]
```

### All Python Files
- [ ] Search for "192.168." and replace with config reads
- [ ] Search for client domain names
- [ ] Check for any passwords or API keys
- [ ] Remove any debug print statements with sensitive data

### Configuration Files
- [ ] Verify no hardcoded credentials
- [ ] Check bec_config.json for client-specific whitelists
- [ ] Verify trusted_domains.json is generic

### Tools/Scripts
- [ ] Check OpenSpacyMenu for client-specific menus
- [ ] Verify scripts don't reference specific servers

## Testing After Sanitization

1. Install on fresh Ubuntu 24.04
2. Verify all configs load from templates
3. Test with generic test domain
4. Ensure no errors referencing production domains

## Files That Should Be Generic

✓ email_filter.py - Reads from email_filter_config.json
✓ modules/*.py - All config-driven
✓ services/db_processor.py - Reads from config
✓ api/*.py - Generic APIs
⚠ web/app.py - **NEEDS REVIEW** (HOSTED_DOMAINS)

