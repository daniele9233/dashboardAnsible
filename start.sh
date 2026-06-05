#!/bin/bash
set -e

cd "$(dirname "$(realpath "$0")")"

# Flask: necessario per servire la dashboard. Su Debian/Ubuntu con PEP 668
# (externally-managed-environment) il modo pulito e' il pacchetto di sistema
# python3-flask; in fallback si usa pip con --break-system-packages.
if ! python3 -c "import flask" 2>/dev/null; then
  echo "  Flask non trovato — installazione in corso…"
  SUDO=""
  if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get install -y python3-flask 2>/dev/null \
      || pip install flask --break-system-packages --quiet 2>/dev/null \
      || pip install flask --user --quiet 2>/dev/null \
      || pip install flask --quiet
  else
    pip install flask --break-system-packages --quiet 2>/dev/null \
      || pip install flask --user --quiet 2>/dev/null \
      || pip install flask --quiet
  fi
fi

# Cartella dove vengono clonati i repository Ansible gestiti dalla dashboard.
export ANSIBLE_PROJECTS_DIR="${ANSIBLE_PROJECTS_DIR:-$HOME/ansible-projects}"

# Porta (override: PORT=9000 ./start.sh)
export PORT="${PORT:-8090}"

echo ""
echo "  Polaris · Ansible Control Plane"
echo "  ─────────────────────────────────────────────"
echo "  URL locale:     http://localhost:$PORT"
echo "  Projects dir:   $ANSIBLE_PROJECTS_DIR"
echo ""
echo "  Accesso da remoto (SSH tunnel):"
echo "  ssh -L $PORT:localhost:$PORT <user>@<controller-ip>"
echo "  Poi apri: http://localhost:$PORT/#/dashboard"
echo "  ─────────────────────────────────────────────"
echo ""

python3 app.py
