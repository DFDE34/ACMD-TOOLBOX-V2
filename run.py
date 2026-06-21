"""
run.py — Lanceur pour ACMD Toolbox V2

  Linux / macOS / Kali  →  Gunicorn  (multi-worker, production-grade)
  Windows               →  python app.py  (serveur Flask intégré)

Variables d'environnement :
  HOST     adresse d'écoute        (défaut : 0.0.0.0)
  PORT     port                    (défaut : 5000)
  WORKERS  workers Gunicorn        (défaut : 2, ignoré sous Windows)
  TIMEOUT  timeout worker (s)      (défaut : 120)
"""

import os, sys

HOST    = os.environ.get('HOST',    '0.0.0.0')
PORT    = os.environ.get('PORT',    '5000')
WORKERS = os.environ.get('WORKERS', '2')
TIMEOUT = os.environ.get('TIMEOUT', '120')

BANNER = f"""
  ╔══════════════════════════════════╗
  ║      ACMD TOOLBOX V2            ║
  ╚══════════════════════════════════╝
  URL  →  http://127.0.0.1:{PORT}
"""

if sys.platform.startswith('win'):
    # ── Windows : serveur Flask intégré (même méthode que python app.py) ──
    from app import app
    print(BANNER + "  Serveur  →  Flask dev (Windows)\n")
    app.run(host=HOST, port=int(PORT), debug=True, threaded=True)

else:
    # ── Linux / macOS / Kali : Gunicorn ──────────────────────────────────
    print(BANNER + f"  Serveur  →  Gunicorn ({WORKERS} workers)\n")
    try:
        os.execvp('gunicorn', [
            'gunicorn',
            f'--bind={HOST}:{PORT}',
            f'--workers={WORKERS}',
            '--threads=4',
            f'--timeout={TIMEOUT}',
            '--access-logfile=-',
            '--error-logfile=-',
            'app:app',
        ])
    except FileNotFoundError:
        print("[ERREUR] Gunicorn non installé.")
        print("         Exécutez : pip install gunicorn")
        sys.exit(1)
