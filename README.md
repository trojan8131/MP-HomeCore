# MP-HomeCore

MP-HomeCore is a Docker-based automation service that **dynamically manages DNS records in Pi-hole and proxy hosts in Nginx Proxy Manager (NPM)** based on Docker container labels.

It connects to a **local Docker socket** or a **remote Docker API**, inspects running containers, reads predefined labels, and automatically:

* Creates or updates **DNS / CNAME records in Pi-hole**
* Creates or updates **Proxy Hosts in Nginx Proxy Manager**
* Applies sane defaults with per-container overrides via labels

This allows you to expose internal services automatically without manually touching Pi-hole or NPM.

---

## ✨ Features

* 🔍 Container discovery via Docker API
* 🏷️ Declarative configuration using Docker labels
* 🌐 Pi-hole DNS & CNAME management via API
* 🔐 Nginx Proxy Manager Proxy Host management via API
* ⚙️ Global defaults with per-service overrides
* 🐳 Works with local Docker socket or remote Docker host
* ⏱️ Scheduled reconciliation (idempotent)

---

## 🧠 How It Works

1. MP-HomeCore connects to Docker (local socket or remote API)
2. It scans all running containers
3. Containers with `MP-HomeCore.*` labels are processed
4. Based on labels and defaults:

   * DNS or CNAME records are created in Pi-hole
   * Proxy Hosts are created in NPM
5. The process repeats every defined interval

---

## 📦 Requirements

* Docker & Docker Compose
* Pi-hole with API access enabled
* Nginx Proxy Manager
* (Optional) `docker-socket-proxy` for secure remote Docker access

---

## 🐳 Docker Compose

### MP-HomeCore

```yaml
services:
  mp-homecore:
    build: .
    container_name: mp-homecore
    volumes:
      - ./config:/app/config:ro
      - ./db:/app/db
      - /var/run/docker.sock:/var/run/docker.sock
    restart: always
```

---

### (Recommended) Docker Socket Proxy

For security reasons, exposing the Docker socket directly is discouraged.

```yaml
services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy:latest
    container_name: mp-homecore-docker-proxy
    restart: unless-stopped
    environment:
      - CONTAINERS=1
      - IMAGES=1
      - INFO=1
      - NETWORKS=1
      - POST=0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "2375:2375"
```

Then set in `config.yaml`:

```yaml
DOCKER_TCP_URL: 'tcp://docker-proxy:2375'
```

---

## 🔁 Scheduler

MP-HomeCore runs a reconciliation loop every:

```yaml
SCHEDULER_INTERVAL_MINUTES: 1
```

Each run:

* Detects new containers
* Updates existing records
* Respects `*_disable=true` flags

---

## 🔐 Security Notes

* Prefer `docker-socket-proxy` over raw `/var/run/docker.sock`
* Use dedicated Pi-hole and NPM credentials
* Restrict NPM access lists where possible

---

## 🚀 Roadmap

* Docker event-driven mode
* Traefik support
* Cloudflare DNS provider
* Ownership / garbage collection of records
* Dry-run mode

---

## 📜 License

MIT License

---

