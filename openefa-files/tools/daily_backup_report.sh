#!/bin/bash
# Generate daily backup report
REPORT_DIR="/opt/spacyserver/reports"
TODAY=$(date +%Y%m%d)

# Ensure the reports directory exists
mkdir -p $REPORT_DIR

# Generate the report
/opt/spacyserver/tools/backup_reporter.py --days 1 --format html --output $REPORT_DIR/backup_report_$TODAY.html

# Create an index file with links to all reports
cat > $REPORT_DIR/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Backup Reports</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; margin: 30px; line-height: 1.6; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        ul { list-style-type: none; padding: 0; }
        li { margin: 10px 0; padding: 12px; background-color: #f8f9fa; border-radius: 5px; transition: all 0.3s; }
        li:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        a { color: #3498db; text-decoration: none; display: block; }
        a:hover { color: #2980b9; }
        .latest { background-color: #e9f7ef; border-left: 5px solid #27ae60; font-weight: bold; }
        .date { color: #7f8c8d; font-size: 0.9em; float: right; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .header h1 { margin: 0; }
        .refresh { background-color: #3498db; color: white; padding: 8px 16px; border-radius: 4px; text-decoration: none; }
        .refresh:hover { background-color: #2980b9; }
        .footer { margin-top: 30px; color: #7f8c8d; font-size: 0.8em; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Backup Reports</h1>
        <a href="index.html" class="refresh">Refresh</a>
    </div>
    <p>View detailed reports on backup status and errors.</p>
    <ul>
EOF

# Add the latest report at the top with special styling
echo "        <li class=\"latest\"><a href=\"backup_report_$TODAY.html\">Latest Report <span class=\"date\">$(date +%Y-%m-%d)</span></a></li>" >> $REPORT_DIR/index.html

# Add links to previous reports (sorted by date, newest first)
find $REPORT_DIR -name "backup_report_*.html" -not -name "backup_report_$TODAY.html" | sort -r | while read report; do
    filename=$(basename "$report")
    date_str=$(echo $filename | sed 's/backup_report_\([0-9]\{8\}\).html/\1/')
    formatted_date=$(date -d "${date_str:0:4}-${date_str:4:2}-${date_str:6:2}" +"%Y-%m-%d" 2>/dev/null)
    
    if [ -n "$formatted_date" ]; then
        echo "        <li><a href=\"$filename\">Backup Report <span class=\"date\">$formatted_date</span></a></li>" >> $REPORT_DIR/index.html
    fi
done

# Close the HTML file
cat >> $REPORT_DIR/index.html << EOF
    </ul>
    <div class="footer">
        Generated at $(date). Backup report server running on $(hostname).
    </div>
</body>
</html>
EOF

# Log that report was generated
echo "Backup report generated at $(date)" >> $REPORT_DIR/report_generation.log
