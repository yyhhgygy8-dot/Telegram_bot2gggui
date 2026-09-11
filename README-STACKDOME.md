# WireGuard Real Panel - Stackdome

This build explicitly sets Flask template_folder to `/app/templates` and includes `templates/login.html`, avoiding TemplateNotFound when deployed from the project root.

## Stackdome
- Build with Dockerfile.
- Expose HTTP port 5000.
- For real WireGuard: the runtime must permit NET_ADMIN/TUN and UDP 51820, or WireGuard must run on the host.
- Persistent volumes: `/data` and `/etc/wireguard`.

Default login: admin / admin123 (change via environment variables).
