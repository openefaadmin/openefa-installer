"""
WSGI Entry Point for SpacyWeb Production Server
Used by Gunicorn to run the Flask application
"""
import sys
import os
import signal
import logging

# Set up paths
sys.path.insert(0, '/opt/spacyserver')
sys.path.insert(0, '/opt/spacyserver/web')

# Import the Flask app
from app import app, get_db_connection, get_hosted_domains, logger, signal_handler

# Set up signal handlers for graceful shutdown
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# Note: Database initialization happens in each worker process via post_fork hook
# Don't initialize DB connections here - Gunicorn workers will do it
logger.info("WSGI module loaded - Gunicorn will initialize workers")

# This is what Gunicorn will use
application = app

if __name__ == "__main__":
    # This won't be called when running under Gunicorn
    # But useful for testing
    print("This should be run via Gunicorn, not directly")
    print("Use: gunicorn -c gunicorn_config.py wsgi:application")
