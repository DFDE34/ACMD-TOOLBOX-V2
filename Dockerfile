# ═══════════════════════════════════════════════════════════════
#  ACMD Toolbox — Image Docker
#  Base : Kali Linux (outils hacking pré-installés)
#  Le conteneur tourne en root → apt-get sans sudo, sans mot de passe
# ═══════════════════════════════════════════════════════════════

FROM kalilinux/kali-rolling:latest

# ── Métadonnées ──────────────────────────────────────────────────
LABEL maintainer="ACMD Toolbox"
LABEL description="Hacker Toolbox — Flask + outils pentest"

# ── Variables d'environnement ─────────────────────────────────────
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production

WORKDIR /app

# ── 1. Dépendances système + outils hacking courants ─────────────
#    Ces outils sont disponibles immédiatement sans installation
#    Ajoutez/retirez selon vos besoins
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    # Runtime Python
    python3 python3-pip python3-venv \
    # Outils réseau de base
    nmap \
    curl wget \
    netcat-openbsd \
    dnsutils \
    whois \
    traceroute \
    iputils-ping \
    net-tools \
    # Outils pentest web
    nikto \
    gobuster \
    dirb \
    wfuzz \
    # Outils pentest généraux
    sqlmap \
    hydra \
    john \
    hashcat \
    masscan \
    aircrack-ng \
    # Utilitaires
    git \
    vim \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Dépendances Python ─────────────────────────────────────────
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# ── 3. Code de l'application ──────────────────────────────────────
COPY app.py .
COPY templates/ ./templates/

# ── 4. Dossier pour la base de données (volume monté) ────────────
RUN mkdir -p /app/data
ENV DB_PATH=/app/data/toolbox.db

# ── 5. Script de démarrage ────────────────────────────────────────
COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── 6. Port exposé ────────────────────────────────────────────────
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]
