#!/bin/bash
set -e

cd "$(dirname "$(realpath "$0")")"

# Installa Flask se manca (richiede pip).
python3 -c "import flask" 2>/dev/null || pip install flask --quiet

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
