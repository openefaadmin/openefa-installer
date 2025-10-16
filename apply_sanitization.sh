#!/bin/bash
# OpenEFA Installer - Apply Sanitization
# This script replaces original files with sanitized versions
# Date: 2025-10-15

set -e

INSTALLER_DIR="/opt/openefa-installer"
BACKUP_DIR="/tmp/openefa-originals-backup-$(date +%Y%m%d_%H%M%S)"

cd "$INSTALLER_DIR"

echo "========================================="
echo " OpenEFA Installer - Sanitization"
echo "========================================="
echo ""
echo "This will replace production data with sanitized versions."
echo "Original files will be backed up to: $BACKUP_DIR"
echo ""
read -p "Continue? (y/n): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Aborted by user"
    exit 1
fi

# Create backup directory
mkdir -p "$BACKUP_DIR"
echo "✅ Created backup directory: $BACKUP_DIR"
echo ""

# Find all .sanitized files and process them
sanitized_count=0
find . -name "*.sanitized" -type f | while read san_file; do
    # Remove the .sanitized extension to get original filename
    orig_file="${san_file%.sanitized}"

    # Backup original
    if [ -f "$orig_file" ]; then
        backup_path="$BACKUP_DIR/$(echo "$orig_file" | sed 's|^\./||' | tr '/' '_')"
        cp "$orig_file" "$backup_path"
        echo "📦 Backed up: $(basename "$orig_file")"
    fi

    # Replace with sanitized version
    mv "$san_file" "$orig_file"
    echo "✅ Replaced: $orig_file"
    echo ""

    ((sanitized_count++))
done

echo "========================================="
echo " Sanitization Complete!"
echo "========================================="
echo ""
echo "Files sanitized: $(find . -type f -path "$BACKUP_DIR/*" | wc -l)"
echo "Backup location: $BACKUP_DIR"
echo ""
echo "Verification:"
echo "-------------"

# Run verification checks
echo -n "Production IPs remaining: "
ip_count=$(grep -r "192\.168\.50\." --include="*.py" --include="*.json" --include="*.sh" . 2>/dev/null | grep -v ".git" | grep -v "SANITIZATION" | wc -l)
if [ "$ip_count" -eq 0 ]; then
    echo "✅ 0 (clean)"
else
    echo "⚠️  $ip_count (review needed)"
fi

echo -n "Production domains remaining: "
domain_count=$(grep -r "covereddata\.com\|seguelogic\.com\|safesoundins\.com" --include="*.py" --include="*.json" --include="*.sh" . 2>/dev/null | grep -v ".git" | grep -v "SANITIZATION" | wc -l)
if [ "$domain_count" -eq 0 ]; then
    echo "✅ 0 (clean)"
else
    echo "⚠️  $domain_count (review needed)"
fi

echo -n "VIP emails remaining: "
email_count=$(grep -r "@seguelogic\|@rdjohnsonlaw\|@chipotlepublishing" --include="*.py" --include="*.json" . 2>/dev/null | grep -v ".git" | grep -v "SANITIZATION" | wc -l)
if [ "$email_count" -eq 0 ]; then
    echo "✅ 0 (clean)"
else
    echo "⚠️  $email_count (review needed)"
fi

echo ""
echo "🎉 Sanitization applied successfully!"
echo ""
echo "Next steps:"
echo "1. Review the sanitized files"
echo "2. Test the installer on a clean system"
echo "3. Commit changes to git: cd $INSTALLER_DIR && git add -A && git commit -m 'Sanitize production data'"
echo "4. Push to GitHub: git push origin main"
echo ""
echo "To restore originals if needed:"
echo "  ls $BACKUP_DIR/"
echo ""
