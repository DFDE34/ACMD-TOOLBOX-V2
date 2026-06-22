# ACMD Toolbox

Interface web de pentest et d'analyse réseau basée sur Flask, tournant sur une image Kali Linux.  
Authentification, RBAC, historique, outils intégrés, outils custom, workflows enchaînés, rapport PDF.

---

## Fonctionnalités

| Module | Détail |
|--------|--------|
| **Fast Tools** | Port scanner, DNS lookup, IP analyser, Subnet calc, Encoder/Decoder, Hash, Regex, César, XOR, Générateur de mots de passe |
| **Scans** | Lancement d'outils en arrière-plan avec historique complet |
| **Workflows** | Enchaînement d'outils sur une cible — exécution en arrière-plan, bouton Arrêter, multitâche |
| **Outils custom** | Ajout de vos propres outils (nmap, gobuster, etc.) avec installation apt intégrée |
| **OWASP Top 10** | Référence des 10 vulnérabilités web critiques |
| **Historique** | Toutes les opérations tracées, filtrables, exportables |
| **Rapport PDF** | Export PDF filtrable par cible et par période |
| **RBAC** | Gestion des rôles (admin / tech / user / pending) avec page d'administration |

---

## Prérequis

| Méthode | Prérequis |
|---------|-----------|
| Docker (recommandé) | Docker Engine + Docker Compose (v2) |
| Python local | Python 3.10+, pip |

---

## Déploiement — Python local (sans Docker)

> Sur **Windows**, cette méthode est adaptée pour un test rapide de l'interface — les outils pentest (nmap, gobuster, etc.) ne seront pas disponibles sans installation manuelle.  
> Sur **Linux / Kali**, c'est une installation complète et fonctionnelle.

### Linux / Kali (recommandé)

> Kali embarque nativement la grande majorité des outils pentest (nmap, gobuster, sqlmap, hydra...).  
> `run.py` détecte automatiquement Linux et lance **Gunicorn** (serveur de production multi-thread).

```bash
git clone https://github.com/DFDE34/ACMD-TOOLBOX-V2.git
cd ACMD-TOOLBOX-V2

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

python3 run.py
```

Accès : **http://localhost:5000**

> `python3 app.py` fonctionne également (serveur Flask dev, pratique pour déboguer).

### Windows (PowerShell)

```powershell
git clone https://github.com/DFDE34/ACMD-TOOLBOX-V2.git
cd ACMD-TOOLBOX-V2

python -m venv venv
.\venv\Scripts\Activate.ps1

pip install -r requirements.txt

python app.py
```

Accès : **http://localhost:5000**

> Sur Windows, les outils intégrés en Python pur (Port Scanner, DNS Lookup, IP Analyser, Subnet Calc) fonctionnent.  
> Les outils custom nécessitent que l'exécutable (nmap, etc.) soit installé et dans le PATH.

---

## Déploiement — Docker

> Méthode recommandée. L'image embarque Kali Linux avec tous les outils pentest pré-installés.

### 1. Cloner le dépôt

```bash
git clone https://github.com/DFDE34/ACMD-TOOLBOX-V2.git
cd ACMD-TOOLBOX-V2
```

### 2. Construire et lancer

```bash
docker compose up -d --build
```

L'application est accessible sur **http://localhost:5000**

---

### Commandes Docker utiles

```bash
# Démarrer (avec rebuild)
docker compose up -d --build

# Voir les logs en temps réel
docker compose logs -f

# Ouvrir un shell dans le conteneur
docker exec -it acmd-toolbox bash

# Tester nmap depuis le conteneur
docker exec acmd-toolbox nmap -sT -p 22,80,443 <cible>

# Arrêter (données conservées)
docker compose down

# Arrêter et supprimer toutes les données
docker compose down -v
```

---

### Comportement réseau selon l'OS

La configuration par défaut utilise `network_mode: host`, ce qui donne au conteneur le même accès réseau que la machine hôte.

| OS hôte | LAN (192.168.x) | Internet | Lab Docker | VPN HTB/THM |
|---------|----------------|----------|------------|-------------|
| **Linux natif** | ✅ Parfait | ✅ | ✅ | ✅ |
| **WSL2 (Windows)** | ⚠️ Partiel | ✅ | ✅ | ✅ |
| **macOS Docker Desktop** | ❌ | ✅ | ✅ | ⚠️ |
| **Windows Docker Desktop** | ❌ | ✅ | ✅ | ⚠️ |

> `network_mode: host` ne fonctionne pas sur Docker Desktop macOS/Windows (VM Linux intermédiaire).  
> Pour scanner un LAN depuis ces OS, utilisez un VPS Linux ou WSL2.

---

### Scénarios réseau

#### Cas 1 — Machines sur le LAN (192.168.x, VMs VirtualBox/VMware)

Fonctionne nativement avec `network_mode: host` (actif par défaut).

```bash
# Depuis l'interface web : lancer un Port Scanner sur 192.168.1.50
# Ou depuis le shell :
docker exec -it acmd-toolbox nmap -sV 192.168.1.50
```

#### Cas 2 — Cibles internet (HackTheBox, TryHackMe, VPS...)

Connectez le VPN sur **la machine hôte** — le conteneur hérite de la connexion.

```bash
# Sur la machine hôte :
sudo openvpn votre_config.ovpn

# Dans l'interface web : scanner 10.10.10.5
# Ou depuis le shell :
docker exec -it acmd-toolbox nmap -sC -sV 10.10.10.5
```

#### Cas 3 — Lab Docker (DVWA, Metasploitable, Juice Shop...)

Décommentez dans `docker-compose.yml` les sections `networks` et les services cibles :

```yaml
# docker-compose.yml
services:
  dvwa:
    image: vulnerables/web-dvwa
    networks:
      pentest-lab:
        ipv4_address: 172.20.0.10

networks:
  pentest-lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

```bash
docker compose up -d
docker exec -it acmd-toolbox nmap -sV 172.20.0.10
```

---

## Premier déploiement — Compte administrateur

Au premier lancement (quelle que soit la méthode), **aucun compte n'existe**. L'application redirige automatiquement vers `/setup` pour créer le compte administrateur initial.

Cette page est **inaccessible** une fois le premier compte créé.

Les comptes suivants créés via `/register` reçoivent le rôle **pending** par défaut — l'administrateur doit leur attribuer un rôle depuis la page **Administration**.

---

## Gestion des rôles (RBAC)

| Rôle | Accès |
|------|-------|
| `admin` | Accès complet + page Administration (gestion des utilisateurs et rôles) |
| `tech` | Scans, Workflows, Outils, Historique, Rapport PDF, Fast Tools |
| `user` | Fast Tools, Historique, Rapport PDF, OWASP Top 10 |
| `pending` | Aucun accès — en attente d'attribution de rôle par un admin |

L'inscription peut être activée ou désactivée depuis la page **Administration**.

---

## Lanceur run.py

`run.py` est utilisé **uniquement en déploiement local** (pas Docker). Il choisit automatiquement le bon serveur selon la plateforme :

| Plateforme | Serveur | Commande |
|------------|---------|----------|
| Linux / Kali / macOS | Gunicorn (2 workers, 4 threads) | `python3 run.py` |
| Windows | Flask dev (threaded) | `python run.py` ou `python app.py` |

> En **Docker**, c'est `docker-entrypoint.sh` qui gère le démarrage — il lance Gunicorn directement sans passer par `run.py`.

Variables d'environnement disponibles (déploiement local uniquement) :

| Variable | Défaut | Description |
|----------|--------|-------------|
| `HOST` | `0.0.0.0` | Adresse d'écoute |
| `PORT` | `5000` | Port |
| `WORKERS` | `2` | Workers Gunicorn (Linux uniquement) |
| `TIMEOUT` | `120` | Timeout worker en secondes (Linux uniquement) |

---

## Outils pré-installés dans l'image Docker

| Outil | Catégorie | Usage |
|-------|-----------|-------|
| `nmap` | Réseau | Scan de ports, détection OS/services |
| `masscan` | Réseau | Scan de ports ultra-rapide |
| `nikto` | Web | Scan de vulnérabilités web |
| `gobuster` | Web | Brute-force répertoires/DNS |
| `dirb` | Web | Brute-force répertoires |
| `wfuzz` | Web | Fuzzing web |
| `sqlmap` | Exploitation | Injection SQL automatisée |
| `hydra` | Exploitation | Brute-force authentification |
| `john` | Crypto | Cracking de hash (CPU) |
| `hashcat` | Crypto | Cracking de hash (GPU limité en conteneur) |
| `aircrack-ng` | Wi-Fi | Audit de réseaux sans fil |
| `curl` / `wget` | Utilitaires | Requêtes HTTP |
| `whois` / `dig` | Reconnaissance | DNS et WHOIS |

---

## Ajouter un outil custom

1. Aller dans **Outils** > **Ajouter un outil**
2. Renseigner le nom, la commande avec placeholder, les options par défaut
3. Si l'outil n'est pas installé, l'interface propose l'installation via `apt-get` (Docker / Linux uniquement)

### Placeholders disponibles — cible : `https://192.168.1.1:5000/api`

| Placeholder | Valeur injectée | Exemple |
|-------------|-----------------|---------|
| `{target}` | Cible telle que saisie | `https://192.168.1.1:5000/api` |
| `{host}` | Hostname / IP seul | `192.168.1.1` |
| `{port}` | Port seul | `5000` |
| `{base_url}` | URL sans le path | `https://192.168.1.1:5000` |
| `{host_port}` | host:port | `192.168.1.1:5000` |

### Sans placeholder — cible ajoutée automatiquement

La cible est insérée juste après la commande, avant les options.  
Si la cible est une URL, **seul le hostname est extrait** (le `https://` et le port sont ignorés).

```
Commande : nikto -h   Options : -Tuning 1   Cible : 192.168.1.1
Exécuté  : nikto -h 192.168.1.1 -Tuning 1
```

> ⚠ **Outils web (gobuster, feroxbuster, ffuf…)** — sans placeholder, le port et le `https://` sont perdus.  
> Utilisez `{base_url}` pour ces outils : `gobuster dir -u {base_url}`

---

## Structure du projet

```
ACMD-TOOLBOX-V2/
├── app.py                  # Application Flask (routes, logique, base de données)
├── run.py                  # Lanceur universel (Gunicorn sur Linux, Flask dev sur Windows)
├── reporting.py            # Génération des rapports PDF (ReportLab)
├── requirements.txt        # Dépendances Python
├── Dockerfile              # Image Kali Linux + outils pentest
├── docker-compose.yml      # Orchestration Docker
├── docker-entrypoint.sh    # Script de démarrage du conteneur
└── templates/
    ├── base.html           # Layout principal (nav filtrée par rôle)
    ├── login.html          # Authentification
    ├── register.html       # Création de compte
    ├── setup.html          # Assistant premier déploiement (création admin)
    ├── waiting.html        # Page d'attente pour les comptes pending
    ├── admin.html          # Administration RBAC (gestion utilisateurs et rôles)
    ├── dashboard.html      # Tableau de bord
    ├── tools.html          # Fast Tools
    ├── scans.html          # Gestionnaire de scans
    ├── scan_tools.html     # Gestion des outils custom
    ├── workflows.html      # Workflows (exécution arrière-plan)
    ├── history.html        # Historique
    ├── report.html         # Rapport PDF
    └── owasp.html          # OWASP Top 10
```

---

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `DB_PATH` | `toolbox.db` | Chemin de la base SQLite (Docker : `/app/data/toolbox.db`) |
| `HOST` | `0.0.0.0` | Adresse d'écoute (run.py) |
| `PORT` | `5000` | Port d'écoute (run.py) |
| `WORKERS` | `2` | Workers Gunicorn — Linux uniquement (run.py) |
| `TIMEOUT` | `120` | Timeout worker en secondes — Linux uniquement (run.py) |

---

## Dépannage

**Le port 5000 est déjà utilisé**
```bash
# Changer le port dans docker-compose.yml :
ports:
  - "8080:5000"
# Accès : http://localhost:8080
```

**nmap -sS (SYN scan) ne fonctionne pas**
```yaml
# docker-compose.yml : passer privileged à true
privileged: true
```

**Les données sont perdues après `docker compose down`**
```bash
# Utiliser down sans -v pour conserver le volume :
docker compose down        # ✅ données conservées
docker compose down -v     # ❌ données supprimées
```

**Mot de passe sudo requis pour installer un outil (mode local)**

Fournissez votre mot de passe sudo dans le formulaire d'installation, ou installez manuellement :
```bash
sudo apt-get install -y <paquet>
```

**Gunicorn non installé sur Linux**
```bash
pip install gunicorn
# ou
pip install -r requirements.txt
```
