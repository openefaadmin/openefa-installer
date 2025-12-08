#!/bin/bash
# Precise MySQL Health Check - Only alert on REAL problems

ERROR=0
MESSAGES=""

# Load database credentials from environment file
if [ -f /etc/spacy-server/.env ]; then
    source /etc/spacy-server/.env
    export MYSQL_PWD="$DB_PASSWORD"
    DB_USER="${DB_USER:-spacy_user}"
    DB_HOST="${DB_HOST:-localhost}"
    DB_NAME="${DB_NAME:-spacy_email_db}"
else
    ERROR=1
    MESSAGES="${MESSAGES}CRITICAL: Cannot find /etc/spacy-server/.env\n"
fi

# 1. Check if MySQL service is running
if ! systemctl is-active --quiet mysql; then
    ERROR=1
    MESSAGES="${MESSAGES}CRITICAL: MySQL service is not running\n"
fi

# 2. Check if we can connect to MySQL
if ! mysqladmin -u"$DB_USER" -h"$DB_HOST" ping -s >/dev/null 2>&1; then
    ERROR=1
    MESSAGES="${MESSAGES}CRITICAL: Cannot ping MySQL server\n"
fi

# 3. Check for connection FAILURES (not client disconnects)
ABORTED_CONNECTS=$(mysql -u"$DB_USER" -h"$DB_HOST" -s -N -e "SHOW STATUS LIKE 'Aborted_connects'" 2>/dev/null | awk '{print $2}')
if [ "$ABORTED_CONNECTS" -gt 10 ]; then
    ERROR=1
    MESSAGES="${MESSAGES}WARNING: ${ABORTED_CONNECTS} failed connection attempts (authentication/network issues)\n"
fi

# 4. Test actual database query
if ! mysql -u"$DB_USER" -h"$DB_HOST" "$DB_NAME" -e "SELECT 1" >/dev/null 2>&1; then
    ERROR=1
    MESSAGES="${MESSAGES}CRITICAL: Cannot execute queries on MySQL\n"
fi

# 5. Check connection count (warn if maxed out)
THREADS=$(mysql -u"$DB_USER" -h"$DB_HOST" -s -N -e "SHOW STATUS LIKE 'Threads_connected'" 2>/dev/null | awk '{print $2}')
MAX_CONN=$(mysql -u"$DB_USER" -h"$DB_HOST" -s -N -e "SHOW VARIABLES LIKE 'max_connections'" 2>/dev/null | awk '{print $2}')
USAGE=$((THREADS * 100 / MAX_CONN))

if [ "$USAGE" -gt 90 ]; then
    ERROR=1
    MESSAGES="${MESSAGES}WARNING: MySQL connections at ${USAGE}% (${THREADS}/${MAX_CONN})\n"
fi

# Return results
if [ "$ERROR" -eq 1 ]; then
    echo -e "MySQL Health Check FAILED:\n${MESSAGES}"
    exit 1
else
    echo "MySQL Health Check: OK (${THREADS} connections, service running)"
    exit 0
fi
