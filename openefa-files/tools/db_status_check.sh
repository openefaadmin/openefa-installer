#!/bin/bash
# SpaCy MySQL Database Status Check and Recovery Script
# Check database status and provide recovery options

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SPACY_ROOT="/opt/spacyserver"
MYSQL_CONFIG="$SPACY_ROOT/config/.my.cnf"
BACKUP_DIR="$SPACY_ROOT/backups"
DB_NAME="spacy_email_db"

echo -e "${BLUE}=== SpaCy MySQL Database Status Check ===${NC}"
echo ""

# Check if MySQL config exists
if [[ -f "$MYSQL_CONFIG" ]]; then
    echo -e "${GREEN}✓${NC} MySQL config found: $MYSQL_CONFIG"
    
    # Extract database details from .my.cnf
    if [[ -r "$MYSQL_CONFIG" ]]; then
        DB_HOST=$(grep -E "^host\s*=" "$MYSQL_CONFIG" | cut -d'=' -f2 | xargs 2>/dev/null || echo "localhost")
        DB_PORT=$(grep -E "^port\s*=" "$MYSQL_CONFIG" | cut -d'=' -f2 | xargs 2>/dev/null || echo "3306")
        DB_USER=$(grep -E "^user\s*=" "$MYSQL_CONFIG" | cut -d'=' -f2 | xargs 2>/dev/null || echo "spacy_user")
        
        echo -e "${BLUE}Database Details:${NC}"
        echo -e "  Config: $MYSQL_CONFIG"
        echo -e "  Host: $DB_HOST"
        echo -e "  Port: $DB_PORT"
        echo -e "  Database: $DB_NAME"
        echo -e "  User: $DB_USER"
    else
        echo -e "${YELLOW}⚠${NC} Cannot read MySQL config file"
        DB_HOST="localhost"
        DB_PORT="3306"
        DB_USER="spacy_user"
    fi
else
    echo -e "${RED}✗${NC} MySQL config not found: $MYSQL_CONFIG"
    echo -e "${YELLOW}Using default values${NC}"
    DB_HOST="localhost"
    DB_PORT="3306"
    DB_USER="spacy_user"
fi

echo ""

# Test database connectivity
echo -e "${BLUE}Testing MySQL Database Connectivity...${NC}"

if command -v mysql >/dev/null 2>&1; then
    # Test connection using config file
    if mysql --defaults-file="$MYSQL_CONFIG" "$DB_NAME" -e "SELECT 1;" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Database connection successful"
        
        # Check if database exists and get table info
        echo ""
        echo -e "${BLUE}Database Content Analysis:${NC}"
        
        # Get database size
        DB_SIZE=$(mysql --defaults-file="$MYSQL_CONFIG" -e "
            SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Database Size (MB)' 
            FROM information_schema.tables 
            WHERE table_schema='$DB_NAME';" -s -N 2>/dev/null)
        
        if [[ -n "$DB_SIZE" ]]; then
            echo -e "${BLUE}Database size: ${DB_SIZE} MB${NC}"
        fi
        
        # Get table list and row counts
        TABLES=$(mysql --defaults-file="$MYSQL_CONFIG" "$DB_NAME" -e "SHOW TABLES;" -s -N 2>/dev/null)
        
        if [[ -n "$TABLES" ]]; then
            echo -e "${GREEN}Tables found:${NC}"
            
            total_emails=0
            while IFS= read -r table; do
                if [[ -n "$table" ]]; then
                    count=$(mysql --defaults-file="$MYSQL_CONFIG" "$DB_NAME" -e "SELECT COUNT(*) FROM \`$table\`;" -s -N 2>/dev/null)
                    echo -e "  $table: $count rows"
                    
                    # If this looks like the main email table, track it
                    if [[ "$table" =~ email|analysis|processed ]]; then
                        total_emails=$((total_emails + count))
                    fi
                fi
            done <<< "$TABLES"
            
            echo ""
            if [[ $total_emails -eq 0 ]]; then
                echo -e "${RED}🚨 DATABASE APPEARS TO BE EMPTY!${NC}"
                echo -e "${YELLOW}  All email analysis tables have 0 rows${NC}"
            else
                echo -e "${GREEN}✓${NC} Database contains $total_emails email records"
            fi
            
        else
            echo -e "${RED}✗${NC} No tables found in database"
            echo -e "${YELLOW}Database exists but appears to be empty or inaccessible${NC}"
        fi
        
        # Check for recent activity
        echo ""
        echo -e "${BLUE}Recent Activity Check:${NC}"
        
        # Try to find tables with timestamps
        TIMESTAMP_TABLES=$(mysql --defaults-file="$MYSQL_CONFIG" -e "
            SELECT DISTINCT table_name, column_name 
            FROM information_schema.columns 
            WHERE table_schema = '$DB_NAME' 
            AND (column_name LIKE '%timestamp%' OR column_name LIKE '%created%' OR column_name LIKE '%date%')
            LIMIT 5;" -s -N 2>/dev/null)
        
        if [[ -n "$TIMESTAMP_TABLES" ]]; then
            echo -e "${GREEN}Timestamp columns found:${NC}"
            echo "$TIMESTAMP_TABLES" | while read -r line; do
                echo -e "  $line"
            done
            
            # Try to get most recent activity
            RECENT_ACTIVITY=$(mysql --defaults-file="$MYSQL_CONFIG" "$DB_NAME" -e "
                SELECT table_name, MAX(create_time) as last_activity 
                FROM information_schema.tables 
                WHERE table_schema = '$DB_NAME' 
                AND create_time IS NOT NULL 
                GROUP BY table_name 
                ORDER BY last_activity DESC 
                LIMIT 3;" -s -N 2>/dev/null)
            
            if [[ -n "$RECENT_ACTIVITY" ]]; then
                echo -e "${GREEN}Recent table activity:${NC}"
                echo "$RECENT_ACTIVITY" | while read -r line; do
                    echo -e "  $line"
                done
            fi
        else
            echo -e "${YELLOW}No timestamp columns found for activity analysis${NC}"
        fi
        
        # Check MySQL process list for current activity
        echo ""
        echo -e "${BLUE}Current MySQL Activity:${NC}"
        PROCESSES=$(mysql --defaults-file="$MYSQL_CONFIG" -e "SHOW PROCESSLIST;" 2>/dev/null | grep -v "Sleep" | wc -l)
        echo -e "Active MySQL connections: $PROCESSES"
        
    else
        echo -e "${RED}✗${NC} Cannot connect to MySQL database"
        echo -e "${YELLOW}  Check if MySQL is running: systemctl status mysql${NC}"
        echo -e "${YELLOW}  Verify connection details in $MYSQL_CONFIG${NC}"
        echo -e "${YELLOW}  Check if database '$DB_NAME' exists${NC}"
        
        # Try to connect without specifying database
        if mysql --defaults-file="$MYSQL_CONFIG" -e "SELECT 1;" >/dev/null 2>&1; then
            echo -e "${YELLOW}  MySQL server is accessible, but database '$DB_NAME' may not exist${NC}"
            
            # Check if database exists
            DB_EXISTS=$(mysql --defaults-file="$MYSQL_CONFIG" -e "SHOW DATABASES LIKE '$DB_NAME';" -s -N 2>/dev/null)
            if [[ -z "$DB_EXISTS" ]]; then
                echo -e "${RED}  Database '$DB_NAME' does not exist!${NC}"
            fi
        fi
    fi
else
    echo -e "${RED}✗${NC} mysql command not found"
    echo -e "${YELLOW}Install MySQL client: apt-get install mysql-client${NC}"
fi

echo ""

# Check MySQL service status
echo -e "${BLUE}MySQL Service Status:${NC}"
if systemctl is-active --quiet mysql; then
    echo -e "${GREEN}✓${NC} MySQL service is running"
    
    # Get MySQL version and status
    MYSQL_VERSION=$(mysql --defaults-file="$MYSQL_CONFIG" -e "SELECT VERSION();" -s -N 2>/dev/null)
    if [[ -n "$MYSQL_VERSION" ]]; then
        echo -e "${BLUE}MySQL version: $MYSQL_VERSION${NC}"
    fi
    
    # Check MySQL error log for recent issues
    if [[ -f "/var/log/mysql/error.log" ]]; then
        RECENT_ERRORS=$(grep -i "error\|warning" /var/log/mysql/error.log | tail -5 2>/dev/null)
        if [[ -n "$RECENT_ERRORS" ]]; then
            echo -e "${YELLOW}Recent MySQL errors/warnings:${NC}"
            echo "$RECENT_ERRORS" | while read -r line; do
                echo -e "  $line"
            done
        fi
    fi
    
else
    echo -e "${RED}✗${NC} MySQL service is not running"
    echo -e "${YELLOW}Start with: systemctl start mysql${NC}"
fi

echo ""

# Check for backup files
echo -e "${BLUE}Backup Analysis:${NC}"

if [[ -d "$BACKUP_DIR" ]]; then
    # Look for database backups
    DB_BACKUPS=$(find "$BACKUP_DIR" -name "*database*" -o -name "*db*" -o -name "*.sql" -o -name "*.dump" -o -name "*mysql*" 2>/dev/null)
    
    if [[ -n "$DB_BACKUPS" ]]; then
        echo -e "${GREEN}✓${NC} Database backup files found:"
        echo "$DB_BACKUPS" | while read -r backup; do
            if [[ -f "$backup" ]]; then
                backup_date=$(stat -c %y "$backup" 2>/dev/null | cut -d' ' -f1-2)
                backup_size=$(stat -c %s "$backup" 2>/dev/null | numfmt --to=iec 2>/dev/null || echo "unknown")
                echo -e "  $(basename "$backup") - $backup_date ($backup_size)"
            fi
        done
    else
        echo -e "${YELLOW}⚠${NC} No database backup files found in $BACKUP_DIR"
    fi
    
    # Look for general backups
    GENERAL_BACKUPS=$(find "$BACKUP_DIR" -name "*.backup.*" 2>/dev/null | head -5)
    if [[ -n "$GENERAL_BACKUPS" ]]; then
        echo ""
        echo -e "${BLUE}Recent general backups:${NC}"
        echo "$GENERAL_BACKUPS" | while read -r backup; do
            if [[ -f "$backup" ]]; then
                backup_date=$(stat -c %y "$backup" 2>/dev/null | cut -d' ' -f1-2)
                echo -e "  $(basename "$backup") - $backup_date"
            fi
        done
    fi
else
    echo -e "${YELLOW}⚠${NC} Backup directory not found: $BACKUP_DIR"
fi

echo ""

# Check SpaCy logs for clues
echo -e "${BLUE}Log Analysis for Database Issues:${NC}"

LOG_LOCATIONS=(
    "/var/log/spacy"
    "/opt/spacyserver/logs"
    "/var/log/mail.log"
    "/var/log/syslog"
    "/var/log/mysql"
)

for log_location in "${LOG_LOCATIONS[@]}"; do
    if [[ -d "$log_location" ]] || [[ -f "$log_location" ]]; then
        echo -e "${GREEN}Checking ${log_location}...${NC}"
        
        # Look for database-related errors in recent logs
        if [[ -d "$log_location" ]]; then
            recent_db_errors=$(find "$log_location" -name "*.log" -mtime -7 -exec grep -l -i "database\|mysql\|spacy_email_db\|empty\|truncate\|drop\|delete" {} \; 2>/dev/null | head -3)
            if [[ -n "$recent_db_errors" ]]; then
                echo -e "  Found database references in recent logs:"
                echo "$recent_db_errors" | while read -r logfile; do
                    echo -e "    $(basename "$logfile")"
                done
            fi
        elif [[ -f "$log_location" ]]; then
            if grep -q -i "database\|mysql\|spacy_email_db" "$log_location" 2>/dev/null; then
                echo -e "  Found database references in $log_location"
                # Show last few relevant lines
                recent_entries=$(grep -i "database\|mysql\|spacy_email_db" "$log_location" | tail -3 2>/dev/null)
                if [[ -n "$recent_entries" ]]; then
                    echo "$recent_entries" | while read -r entry; do
                        echo -e "    $entry"
                    done
                fi
            fi
        fi
    fi
done

echo ""

# Recovery recommendations
echo -e "${BLUE}=== Recovery Recommendations ===${NC}"

if [[ $total_emails -eq 0 ]]; then
    echo -e "${RED}🚨 DATABASE IS EMPTY - IMMEDIATE ACTION NEEDED${NC}"
    echo ""
    echo -e "${YELLOW}Immediate Steps:${NC}"
    echo -e "1. Stop email processing: systemctl stop postfix"
    echo -e "2. Check MySQL service: systemctl status mysql"
    echo -e "3. Look for any running database maintenance"
    echo -e "4. Check for recent backup files (see above)"
    echo -e "5. Check system logs for what happened"
    echo ""
    echo -e "${YELLOW}Recovery Options:${NC}"
    echo -e "1. Restore from MySQL backup if available:"
    echo -e "   mysql --defaults-file=$MYSQL_CONFIG $DB_NAME < /path/to/backup.sql"
    echo -e "2. Check if data was moved to another database/location"
    echo -e "3. Reinitialize database schema if needed"
    echo -e "4. Resume email processing (data will rebuild over time)"
    echo ""
    echo -e "${BLUE}To reinitialize the database:${NC}"
    echo -e "cd /opt/spacyserver && python3 -c \"from modules.email_database import get_database_handler; get_database_handler().initialize_database()\""
    
else
    echo -e "${GREEN}✓${NC} Database appears to have data ($total_emails records)"
    echo -e "${BLUE}Monitoring Recommendations:${NC}"
    echo -e "1. Set up automated MySQL backups"
    echo -e "2. Monitor database growth and performance"
    echo -e "3. Check disk space regularly"
    echo -e "4. Review MySQL error logs periodically"
fi

echo ""

# MySQL-specific recovery commands
echo -e "${BLUE}=== MySQL-Specific Commands ===${NC}"
echo -e "Connect to database:"
echo -e "  mysql --defaults-file=$MYSQL_CONFIG $DB_NAME"
echo ""
echo -e "Create database backup:"
echo -e "  mysqldump --defaults-file=$MYSQL_CONFIG $DB_NAME > spacy_backup_\$(date +%Y%m%d_%H%M%S).sql"
echo ""
echo -e "Restore from backup:"
echo -e "  mysql --defaults-file=$MYSQL_CONFIG $DB_NAME < backup_file.sql"
echo ""
echo -e "Check database size:"
echo -e "  mysql --defaults-file=$MYSQL_CONFIG -e \"SELECT table_schema AS 'Database', ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)' FROM information_schema.tables WHERE table_schema='$DB_NAME';\""

echo ""
echo -e "${BLUE}=== End Database Analysis ===${NC}"
