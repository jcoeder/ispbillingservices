# gunicorn.conf.py - Configuration for Gunicorn

# Bind to Unix socket (matches systemd service)
bind = 'unix:/tmp/isp-circuit-invoice-tracker.sock'

# Number of worker processes (adjust based on CPU cores)
workers = 3

# Worker type (sync is fine for most apps; use gevent for async if needed)
worker_class = 'sync'

# Permissions for the socket (007 means owner: rwx, group: none, others: none)
umask = 0o007

# Logging
loglevel = 'info'
accesslog = '-'
errorlog = '-'

# Timeout for workers (increase if your app has long-running requests)
timeout = 30

# Max requests per worker before restart (prevents memory leaks)
max_requests = 1000
max_requests_jitter = 50