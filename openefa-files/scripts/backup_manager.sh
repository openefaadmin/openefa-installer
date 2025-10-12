#!/bin/bash
##############################################################################
# SpaCy Backup Manager
# Purpose: Manage backups for SpaCy email filter safely
##############################################################################

BACKUP_DIR="/opt/spacyserver/backups"
EMAIL_FILTER="/opt/spacyserver/email_filter.py"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Function to create backup
create_backup() {
    local backup_name="$1"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/email_filter.py.backup.${backup_name}.${timestamp}"
    
    if [ -f "$EMAIL_FILTER" ]; then
        cp "$EMAIL_FILTER" "$backup_file"
        echo "✅ Backup created: $backup_file"
        return 0
    else
        echo "❌ Source file not found: $EMAIL_FILTER"
        return 1
    fi
}

# Function to list backups
list_backups() {
    echo "📋 Available backups in $BACKUP_DIR:"
    if ls "$BACKUP_DIR"/email_filter.py.backup.* 1> /dev/null 2>&1; then
        ls -la "$BACKUP_DIR"/email_filter.py.backup.* | while read line; do
            echo "  $line"
        done
    else
        echo "  No backups found"
    fi
}

# Main menu
case "${1:-menu}" in
    "emergency")
        echo "🚨 Creating emergency backup before applying fixes..."
        create_backup "emergency"
        ;;
    "list")
        list_backups
        ;;
    *)
        echo "=== SpaCy Backup Manager ==="
        echo "Usage: $0 <command>"
        echo "  emergency    - Quick emergency backup"
        echo "  list         - List all available backups"
        ;;
esac
