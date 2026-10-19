# gunicorn.conf.py
bind = "127.0.0.1:5000"
workers = 2                # 2 vCPU → 2 workers (generator already uses 150 threads internally)
worker_class = "gthread"
threads = 16
timeout = 180              # 150 workers × slow CF wait → বাড়িয়ে দিলাম
graceful_timeout = 30
keepalive = 10
max_requests = 500
max_requests_jitter = 50
accesslog = "-"
errorlog = "-"
loglevel = "info"