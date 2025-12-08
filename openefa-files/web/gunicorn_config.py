"""
Gunicorn Configuration for SpacyWeb Production Server
"""
import multiprocessing
import os

# Server socket
bind = "127.0.0.1:5500"
backlog = 2048

# Worker processes
# Reduced from (cpu_count * 2 + 1 = 9) to 4 to prevent DB connection exhaustion
# Each worker creates a pool of 20 DB connections, so 4 workers = 80 connections max
workers = 4  # Conservative: 4 CPUs = 4 workers (adjust based on load)
worker_class = 'sync'  # Use 'gevent' or 'eventlet' for async if needed
worker_connections = 1000
max_requests = 1000  # Restart workers after N requests (prevents memory leaks)
max_requests_jitter = 50  # Add randomness to prevent all workers restarting at once
timeout = 120  # Worker timeout (2 minutes for long-running requests)
keepalive = 5  # Keep-alive connections

# SSL/TLS Configuration
certfile = '/opt/spacyserver/web/certs/cert.pem'
keyfile = '/opt/spacyserver/web/certs/key.pem'
ssl_version = 5  # TLS 1.2+
cert_reqs = 0  # Don't require client certificates

# Logging
accesslog = '/opt/spacyserver/logs/gunicorn_access.log'
errorlog = '/opt/spacyserver/logs/gunicorn_error.log'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'spacyweb'

# Server mechanics
daemon = False  # systemd manages the process
pidfile = '/tmp/spacyweb.pid'
user = None  # systemd sets the user
group = None  # systemd sets the group
umask = 0
tmp_upload_dir = None

# Security
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# Server hooks
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting Gunicorn server")

def on_reload(server):
    """Called to recycle workers during a reload."""
    server.log.info("Reloading Gunicorn server")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("Gunicorn server is ready. Spawning workers")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info(f"Worker spawned (pid: {worker.pid})")

def post_worker_init(worker):
    """Called just after a worker has initialized the application."""
    worker.log.info(f"Worker initialized (pid: {worker.pid})")

    # Load hosted domains from database into each worker
    try:
        from app import get_hosted_domains, HOSTED_DOMAINS
        import app as app_module
        domains = get_hosted_domains()
        app_module.HOSTED_DOMAINS = domains
        worker.log.info(f"Loaded {len(domains)} hosted domains from database")
        if domains:
            worker.log.info(f"Active domains: {', '.join(domains)}")
    except Exception as e:
        worker.log.error(f"Failed to load hosted domains: {e}")

def worker_exit(server, worker):
    """Called just after a worker has been exited."""
    server.log.info(f"Worker exited (pid: {worker.pid})")
