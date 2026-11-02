# Reverse proxy with TLS for ASM Sentinel

ASM Sentinel listens on `127.0.0.1:8000` by default and does not terminate TLS
itself. Put nginx in front before exposing the interface beyond localhost.

```nginx
# /etc/nginx/sites-available/asm-sentinel
server {
    listen 80;
    server_name asm.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name asm.example.com;

    ssl_certificate     /etc/letsencrypt/live/asm.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/asm.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Scanning can take hours; do not cut the connection while the UI polls.
    proxy_read_timeout 300s;

    # Optional: restrict access by IP or basic auth in addition to the app login.
    # allow 203.0.113.0/24;
    # deny all;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

Enable and reload:

```bash
sudo ln -s /etc/nginx/sites-available/asm-sentinel /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

After enabling HTTPS, set `ASM_COOKIE_SECURE=1` in
`/etc/asm-sentinel/asm-sentinel.env` and restart the service:

```bash
sudo systemctl restart asm-sentinel
```

With a proxy in front, `request.client.host` becomes the proxy address, so the
login rate limiter sees a single IP. If you need per-client limits, configure
`X-Real-IP` handling at the proxy level.
