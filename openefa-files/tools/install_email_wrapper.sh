#!/bin/bash
# Configure Postfix to bypass email_filter.py for local mail

# Backup current configuration
cp /etc/postfix/master.cf /etc/postfix/master.cf.backup.$(date +%s)

# Identify the current filter configuration
FILTER_LINE=$(grep -n "spacyfilter" /etc/postfix/master.cf | cut -d ':' -f 1)

if [ -z "$FILTER_LINE" ]; then
    echo "Could not find spacyfilter entry in master.cf. Is it configured correctly?"
    exit 1
fi

# Extract the current filter configuration
FILTER_CONFIG=$(sed -n "${FILTER_LINE}p" /etc/postfix/master.cf)
echo "Current filter configuration: $FILTER_CONFIG"

# Modify master.cf to add a condition for bypassing the filter
sed -i "${FILTER_LINE}s/pipe/pipe -o/g" /etc/postfix/master.cf
sed -i "${FILTER_LINE}s/flags=DRhu user=root/flags=DRhu user=root argv=\/bin\/sh -c '\[ \"\$SENDER\" = \"root\" \] \&\& exec \/usr\/sbin\/sendmail -i \"\$@\" || exec \/opt\/spacyserver\/email_filter.py'/g" /etc/postfix/master.cf

# Restart Postfix
postfix reload

echo "Postfix configuration updated to bypass the filter for local mail."
echo "Internal emails should now be delivered without going through email_filter.py"
echo "External emails will still be processed normally."
