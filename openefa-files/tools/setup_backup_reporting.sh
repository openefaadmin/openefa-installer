#!/bin/bash
# Setup script for backup reporting on port 5005

# Create a directory for backup reports
mkdir -p /opt/spacyserver/reports

# Create a script that will run the HTTP server
cat > /opt/spacyserver/tools/report_server.py << 'EOL'
#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys
import datetime
import argparse

# Default configuration
DEFAULT_PORT = 5005
DEFAULT_DIRECTORY = "/opt/spacyserver/reports"

class ReportHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Pass the directory to serve
        super().__init__(*args, directory=self.directory, **kwargs)
    
    def log_message(self, format, *args):
        # Enhanced logging with date and time
        sys.stdout.write("[%s] %s\n" % (self.log_date_time_string(), format % args))

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="HTTP Server for Backup Reports")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port to serve on (default: {DEFAULT_PORT})")
    parser.add_argument("--dir", default=DEFAULT_DIRECTORY, help=f"Directory to serve (default: {DEFAULT_DIRECTORY})")
    
    args = parser.parse_args()
    
    # Set the directory in the handler class
    ReportHandler.directory = args.dir
    
    # Create the server
    try:
        httpd = socketserver.TCPServer(("", args.port), ReportHandler)
        
        # Start the server
        print(f"Starting HTTP server on port {args.port}...")
        print(f"Serving files from: {args.dir}")
        print(f"Server started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Access the reports at: http://your-server-ip:{args.port}/")
        print("Press Ctrl+C to stop the server")
        
        httpd.serve_forever()
        
    except KeyboardInterrupt:
        print("\nServer stopped.")
    except OSError as e:
        if e.errno == 98:  # Address already in use
            print(f"\nError: Port {args.port} is already in use.")
            print("Try a different port with --port PORT")
        else:
            print(f"\nError: {e}")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()
EOL

# Make the server script executable
chmod +x /opt/spacyserver/tools/report_server.py

# Create a script to generate the daily backup report
cat > /opt/spacyserver/tools/daily_backup_report.sh << 'EOL'
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
EOL

# Make the daily report script executable
chmod +x /opt/spacyserver/tools/daily_backup_report.sh

# Create a systemd service file for the report server
cat > /etc/systemd/system/backup-report-server.service << 'EOL'
[Unit]
Description=Backup Reports HTTP Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/spacyserver/tools/report_server.py --port 5005
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

# Enable and start the service
systemctl daemon-reload
systemctl enable backup-report-server
systemctl start backup-report-server

# Generate an initial report
/opt/spacyserver/tools/daily_backup_report.sh

# Add the daily report generation to crontab
(crontab -l 2>/dev/null; echo "0 7 * * * /opt/spacyserver/tools/daily_backup_report.sh") | crontab -

echo "Setup complete!"
echo "You can now access backup reports at http://your-server-ip:5005/"
echo "A new report will be generated daily at 7:00 AM"
echo "You can manually generate a report anytime by running: /opt/spacyserver/tools/daily_backup_report.sh"
