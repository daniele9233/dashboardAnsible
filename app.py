from flask import Flask, request, jsonify, render_template
import subprocess
import threading
import shlex
import json
import os

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configurazione di base
# ---------------------------------------------------------------------------
# Cartella dove vengono clonati i repository Ansible gestiti dalla dashboard.
# Personalizzabile via env ANSIBLE_PROJECTS_DIR (default: ~/ansible-projects).
PROJECTS_DIR = os.path.abspath(
    os.environ.get('ANSIBLE_PROJECTS_DIR', os.path.expanduser('~/ansible-projects'))
)

# ---------------------------------------------------------------------------
# Registro dei progetti Ansible.
# Ogni voce mappa 1:1 un repository GitHub personale. I metadati (playbook,
# inventory, host groups, roles) sono ricavati dalla struttura reale dei repo.
# ---------------------------------------------------------------------------
PROJECTS = [
    {
        'key': 'microceph',
        'name': 'MicroCeph · Dischi Loop',
        'desc': 'Cluster MicroCeph a 3 nodi con OSD su loop device e CephFS replica 3.',
        'repo': 'https://github.com/daniele9233/microceph-dischi-loop',
        'branch': 'main',
        'subdir': 'ansible',
        'playbook': 'site.yml',
        'inventory': 'inventory.ini',
        'icon': 'hard-drive',
        'accent': '#5aa6ed',
        'groups': ['microceph', 'microceph_bootstrap', 'microceph_workers'],
        'roles': ['microceph_install', 'microceph_bootstrap', 'microceph_join',
                  'microceph_osd', 'microceph_cephfs', 'microceph_verify'],
    },
    {
        'key': 'kafka',
        'name': 'Kafka + Zookeeper',
        'desc': 'Deploy di un cluster Kafka e Zookeeper. NB: il disco /opt va montato manualmente.',
        'repo': 'https://github.com/daniele9233/kafka-zookeeper-ansible',
        'branch': 'main',
        'subdir': '',
        'playbook': 'install.yml',
        'inventory': 'inventories/inventory.ini',
        'icon': 'layers',
        'accent': '#e8a838',
        'groups': ['zookeeper', 'kafka'],
        'roles': ['zookeeper', 'kafka'],
    },
    {
        'key': 'patroni',
        'name': 'Patroni · PostgreSQL HA',
        'desc': 'PostgreSQL 15 in alta affidabilità con Patroni, etcd e PgBouncer su 3 nodi.',
        'repo': 'https://github.com/daniele9233/patroni-cluster',
        'branch': 'main',
        'subdir': '',
        'playbook': 'site.yml',
        'inventory': 'inventory.ini',
        'icon': 'database',
        'accent': '#3fb87a',
        'groups': ['all'],
        'roles': ['postgresql_cluster'],
    },
    {
        'key': 'rke2',
        'name': 'K8s RKE2 + Rancher v5',
        'desc': 'Cluster RKE2 multi-nodo con Rancher, NFS, pgAdmin, Nginx e Prometheus.',
        'repo': 'https://github.com/daniele9233/K8s-RKE2-Rancher-v5',
        'branch': 'main',
        'subdir': '',
        'playbook': 'site.yml',
        'inventory': 'inventory.ini',
        'icon': 'boxes',
        'accent': '#c084fc',
        'groups': ['all', 'masters', 'new_managers', 'workers', 'nfs_server', 'nginx_servers'],
        'roles': ['create_disk', 'update_hosts_file', 'master1_install', 'master1_config',
                  'master1_kubectl', 'master1_helm_cert_manager_install', 'master1_create_cluster',
                  'kubectl_setup', 'nfs', 'nfs_client_setup', 'nfs_provisioner',
                  'install_pgadmin', 'nginx_install', 'install_prometheus'],
    },
]
PROJECTS_BY_KEY = {p['key']: p for p in PROJECTS}

# Operazioni ansible-playbook supportate -> argomenti aggiuntivi.
PLAYBOOK_OPS = {
    'deploy':     [],
    'dryrun':     ['--check', '--diff'],
    'syntax':     ['--syntax-check'],
    'list_tasks': ['--list-tasks'],
    'list_hosts': ['--list-hosts'],
}
# 'ping' è gestita a parte (ansible -m ping, non ansible-playbook).
VALID_OPS = set(PLAYBOOK_OPS) | {'ping'}

# ---------------------------------------------------------------------------
# Stato job (uno alla volta, come nella dashboard di riferimento).
# ---------------------------------------------------------------------------
_job_lock = threading.Lock()
_job_state = {
    'status': 'idle',  # idle | running | success | failed
    'output': [],
}


# ---------------------------------------------------------------------------
# Helper sui path dei progetti
# ---------------------------------------------------------------------------
def _repo_name(p):
    """Nome cartella locale del repo (basename dell'URL, senza .git)."""
    base = p['repo'].rstrip('/').split('/')[-1]
    return base[:-4] if base.endswith('.git') else base


def _project_dir(p):
    """Root del repo clonato."""
    return os.path.join(PROJECTS_DIR, _repo_name(p))


def _work_dir(p):
    """Directory di lavoro ansible (root + eventuale subdir tipo 'ansible')."""
    root = _project_dir(p)
    return os.path.join(root, p['subdir']) if p.get('subdir') else root


def _is_cloned(p):
    return os.path.isdir(os.path.join(_project_dir(p), '.git'))


def _safe_join(base, rel):
    """Join che impedisce path traversal fuori da base. Ritorna None se fuori."""
    full = os.path.normpath(os.path.join(base, rel))
    base = os.path.normpath(base)
    if full != base and not full.startswith(base + os.sep):
        return None
    return full


# ---------------------------------------------------------------------------
# Esecuzione comandi in background con streaming su _job_state['output'].
# ---------------------------------------------------------------------------
def _run(cmd_parts, cwd):
    try:
        env = os.environ.copy()
        env['ANSIBLE_FORCE_COLOR'] = '1'
        env['PYTHONUNBUFFERED'] = '1'

        quoted = ' '.join(shlex.quote(p) for p in cmd_parts)

        proc = subprocess.Popen(
            ['bash', '-c', f'exec {quoted}'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=cwd,
            bufsize=1,
            universal_newlines=True,
        )
        for line in iter(proc.stdout.readline, ''):
            _job_state['output'].append(line.rstrip('\n'))
        proc.wait()
        _job_state['status'] = 'success' if proc.returncode == 0 else 'failed'

    except Exception as exc:
        _job_state['output'].append(f'[ERRORE INTERNO] {exc}')
        _job_state['status'] = 'failed'

    finally:
        _job_lock.release()


def _start_job(cmd_parts, cwd):
    """Acquisisce il lock e avvia _run in un thread. Ritorna (ok, errore)."""
    if not _job_lock.acquire(blocking=False):
        return False, 'Un job è già in esecuzione. Attendi il completamento.'
    _job_state['output'] = []
    _job_state['status'] = 'running'
    t = threading.Thread(target=_run, args=(cmd_parts, cwd), daemon=True)
    t.start()
    return True, None


# ---------------------------------------------------------------------------
# Rotte pagina + streaming output
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/output')
def api_output():
    since = int(request.args.get('since', 0))
    lines = _job_state['output'][since:]
    return jsonify({
        'lines': lines,
        'total': len(_job_state['output']),
        'status': _job_state['status'],
    })


# ---------------------------------------------------------------------------
# Stato dei progetti (con info git: clonato? branch? ultimo commit?)
# ---------------------------------------------------------------------------
def _git(args, cwd, timeout=8):
    try:
        r = subprocess.run(['git'] + args, capture_output=True, text=True,
                           cwd=cwd, timeout=timeout)
        return r.returncode, (r.stdout or '').strip(), (r.stderr or '').strip()
    except Exception as exc:
        return -1, '', str(exc)


def _project_status(p):
    cloned = _is_cloned(p)
    info = {
        'key': p['key'], 'name': p['name'], 'desc': p['desc'], 'repo': p['repo'],
        'branch': p['branch'], 'icon': p['icon'], 'accent': p['accent'],
        'playbook': p['playbook'], 'inventory': p['inventory'],
        'subdir': p.get('subdir', ''), 'groups': p['groups'], 'roles': p['roles'],
        'cloned': cloned, 'head': None, 'currentBranch': None, 'dirty': False,
        'workDir': _work_dir(p),
    }
    if cloned:
        pdir = _project_dir(p)
        _, head, _ = _git(['log', '-1', '--pretty=%h %s'], pdir)
        info['head'] = head or None
        _, br, _ = _git(['rev-parse', '--abbrev-ref', 'HEAD'], pdir)
        info['currentBranch'] = br or None
        _, st, _ = _git(['status', '--porcelain'], pdir)
        info['dirty'] = bool(st)
    return info


@app.route('/api/projects')
def api_projects():
    return jsonify({
        'projects': [_project_status(p) for p in PROJECTS],
        'projectsDir': PROJECTS_DIR,
    })


@app.route('/api/project/clone', methods=['POST'])
def api_project_clone():
    data = request.get_json(force=True, silent=True) or {}
    p = PROJECTS_BY_KEY.get(data.get('key', ''))
    if not p:
        return jsonify({'error': 'Progetto non valido'}), 400

    try:
        os.makedirs(PROJECTS_DIR, exist_ok=True)
    except Exception as exc:
        return jsonify({'error': f'Impossibile creare {PROJECTS_DIR}: {exc}'}), 500

    pdir = _project_dir(p)
    if _is_cloned(p):
        cmd = ['git', '-C', pdir, 'pull', '--ff-only', 'origin', p['branch']]
        cwd = pdir
    else:
        cmd = ['git', 'clone', '--branch', p['branch'], p['repo'], pdir]
        cwd = PROJECTS_DIR

    ok, err = _start_job(cmd, cwd)
    if not ok:
        return jsonify({'error': err}), 409
    return jsonify({'status': 'started'})


# ---------------------------------------------------------------------------
# Esecuzione playbook / comandi ansible
# ---------------------------------------------------------------------------
def _build_command(p, op, limit):
    inv = p['inventory']
    if op == 'ping':
        return ['ansible', (limit or 'all'), '-i', inv, '-m', 'ping']
    cmd = ['ansible-playbook', p['playbook'], '-i', inv]
    if limit:
        cmd += ['--limit', limit]
    cmd += PLAYBOOK_OPS[op]
    return cmd


@app.route('/api/run', methods=['POST'])
def api_run():
    data = request.get_json(force=True, silent=True) or {}
    p = PROJECTS_BY_KEY.get(data.get('project', ''))
    op = data.get('op', '')
    limit = (data.get('limit') or '').strip()

    if not p:
        return jsonify({'error': 'Progetto non valido'}), 400
    if op not in VALID_OPS:
        return jsonify({'error': 'Operazione non valida'}), 400
    if limit and limit not in p['groups']:
        return jsonify({'error': f'Host group non valido: {limit}'}), 400
    if not _is_cloned(p):
        return jsonify({'error': "Repo non clonato. Usa 'Clona / Pull' nella pagina Progetti."}), 409

    wd = _work_dir(p)
    if not os.path.isdir(wd):
        return jsonify({'error': f'Directory di lavoro mancante: {wd}'}), 409

    cmd = _build_command(p, op, limit)
    ok, err = _start_job(cmd, wd)
    if not ok:
        return jsonify({'error': err}), 409
    return jsonify({'status': 'started'})


# ---------------------------------------------------------------------------
# Inventory: parsing dell'inventory.ini del progetto in gruppi -> host
# ---------------------------------------------------------------------------
def _parse_inventory(text):
    groups = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in '#;':
            continue
        if line.startswith('[') and line.endswith(']'):
            name = line[1:-1].strip()
            kind = 'hosts'
            if name.endswith(':vars'):
                kind = 'vars'
            elif name.endswith(':children'):
                kind = 'children'
            current = {'name': name, 'kind': kind, 'lines': []}
            groups.append(current)
            continue
        if current is None:
            # host fuori da ogni sezione -> gruppo implicito "ungrouped"
            current = {'name': 'ungrouped', 'kind': 'hosts', 'lines': []}
            groups.append(current)
        current['lines'].append(line)
    return groups


@app.route('/api/inventory')
def api_inventory():
    p = PROJECTS_BY_KEY.get(request.args.get('project', ''))
    if not p:
        return jsonify({'error': 'Progetto non valido'}), 400
    if not _is_cloned(p):
        return jsonify({'error': 'Repo non clonato', 'cloned': False}), 409

    full = _safe_join(_work_dir(p), p['inventory'])
    if not full:
        return jsonify({'error': 'Path inventory non consentito'}), 403
    try:
        with open(full, 'r', encoding='utf-8') as f:
            text = f.read()
    except FileNotFoundError:
        return jsonify({'error': f"Inventory non trovato: {p['inventory']}"}), 404
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500

    return jsonify({
        'inventory': p['inventory'],
        'groups': _parse_inventory(text),
        'raw': text,
    })


# ---------------------------------------------------------------------------
# File browser: elenco file rilevanti del progetto + lettura singolo file
# ---------------------------------------------------------------------------
def _list_project_files(p):
    wd = _work_dir(p)
    out = []

    def add(rel):
        full = os.path.join(wd, rel)
        if os.path.isfile(full):
            out.append({'path': rel, 'label': rel})

    add(p['playbook'])
    add(p['inventory'])
    add('ansible.cfg')

    gv = os.path.join(wd, 'group_vars')
    if os.path.isdir(gv):
        for fn in sorted(os.listdir(gv)):
            if fn.endswith(('.yml', '.yaml')):
                add(os.path.join('group_vars', fn))

    roles = os.path.join(wd, 'roles')
    if os.path.isdir(roles):
        for role in sorted(os.listdir(roles)):
            main = os.path.join('roles', role, 'tasks', 'main.yml')
            if os.path.isfile(os.path.join(wd, main)):
                add(main)
    return out


@app.route('/api/files')
def api_files():
    p = PROJECTS_BY_KEY.get(request.args.get('project', ''))
    if not p:
        return jsonify({'error': 'Progetto non valido'}), 400
    if not _is_cloned(p):
        return jsonify({'error': 'Repo non clonato', 'cloned': False}), 409

    rel = request.args.get('path')
    wd = _work_dir(p)

    if rel is None:
        return jsonify({'files': _list_project_files(p), 'workDir': wd})

    full = _safe_join(wd, rel)
    if not full:
        return jsonify({'error': 'Path non consentito'}), 403
    try:
        if os.path.getsize(full) > 1_000_000:
            return jsonify({'error': 'File troppo grande (>1MB)'}), 413
        with open(full, 'r', encoding='utf-8') as f:
            return jsonify({'content': f.read(), 'path': rel})
    except FileNotFoundError:
        return jsonify({'error': 'File non trovato'}), 404
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ---------------------------------------------------------------------------
# HOW-TO: documentazione della dashboard (file accanto a app.py)
# ---------------------------------------------------------------------------
@app.route('/api/howto')
def api_howto():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'HOW-TO')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return jsonify({'content': f.read()})
    except FileNotFoundError:
        return jsonify({'content': '# HOW-TO non disponibile.'})
    except Exception as exc:
        return jsonify({'content': f'# Errore: {exc}'})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False, threaded=True)
