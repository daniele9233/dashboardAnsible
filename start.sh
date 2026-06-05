#!/bin/bash
set -e

# Attiva il virtualenv con ansible (se presente). La dashboard funziona anche
# senza venv, usando l'ansible nel PATH.
if [ -f ~/ansible-env/bin/activate ]; then
  source ~/ansible-env/bin/activate
fi

pip install flask --quiet 2>/dev/null || true

cd "$(dirname "$(realpath "$0")")"

# Cartella dove vengono clonati i repository Ansible gestiti dalla dashboard.
export ANSIBLE_PROJECTS_DIR="${ANSIBLE_PROJECTS_DIR:-$HOME/ansible-projects}"

echo ""
echo "  Polaris · Ansible Control Plane"
echo "  ─────────────────────────────────────────────"
echo "  URL locale:     http://localhost:8080"
echo "  Projects dir:   $ANSIBLE_PROJECTS_DIR"
echo ""
echo "  Accesso da Windows (SSH tunnel):"
echo "  ssh -L 8080:localhost:8080 <user>@<controller-ip>"
echo "  Poi apri: http://localhost:8080/#/dashboard"
echo "  ─────────────────────────────────────────────"
echo ""

python app.py
