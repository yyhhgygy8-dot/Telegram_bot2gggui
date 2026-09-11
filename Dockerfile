FROM python:3.11-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iproute2 iptables ca-certificates procps && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /data /etc/wireguard && chmod 700 /etc/wireguard
ENV PORT=5000 WG_INTERFACE=wg0 WG_PORT=51820 WG_SUBNET=10.66.66.0/24 WG_DNS=1.1.1.1
EXPOSE 5000 51820/udp
VOLUME ["/data", "/etc/wireguard"]
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "120", "wsgi:app"]
