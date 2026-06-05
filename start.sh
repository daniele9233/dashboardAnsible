#!/bin/bash
set -e

cd "$(dirname "$(realpath "$0")")"

# Flask: necessario per servire la dashboard. Su Debian/Ubuntu con PEP 668
# (externally-managed-environment) il modo pulito e' il pacchetto di sistema
# python3-flask; in fallback si usa pip con --break-system-packages.
if ! python3 -c "import flask" 2>/dev/null; then
  echo "  Flask non trovato — installazione in corso…"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y python3-flask 2>/dev/null \
      || pip install flask --break-system-packages --quiet 2>/dev/null \
      || pip install flask --quiet
  else
    pip install flask --break-system-packages --quiet 2>/dev/null \
      || pip install flask --quiet
  fi
fi

# Cartella dove vengono clonati i repository Ansible gestiti dalla dashboard.
export ANSIBLE_PROJECTS_DIR="${ANSIBLE_PROJECTS_DIR:-$HOME/ansible-projects}"

echo ""
echo "  Polaris · Ansible Control Plane"
echo "  ─────────────────────────────────────────────"
echo "  URL locale:     http://localhost:8080"
echo "  Projects dir:   $ANSIBLE_PROJECTS_DIR"
echo ""
echo "  Accesso da remoto (SSH tunnel):"
echo "  ssh -L 8080:localhost:8080 <user>@<controller-ip>"
echo "  Poi apri: http://localhost:8080/#/dashboard"
echo "  ─────────────────────────────────────────────"
echo ""

python3 app.py
