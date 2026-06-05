from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone
import subprocess
import threading
import tempfile
import base64
import shlex
import shutil
import json
import time
import re
import os

app = Flask(__name__)

ANSIBLE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
VENV = os.path.expanduser('~/ansible-env')

_job_lock = threading.Lock()
_job_state = {
    'status': 'idle',  # idle | running | success | failed
    'output': [],
}

COMMANDS = {
    'vault_main':             {'exe': 'ansible-vault',    'args': ['view', 'group_vars/all/vault.yml'],                                          'needs_vault': True},
    'vault_cavalid':          {'exe': 'ansible-vault',    'args': ['view', 'group_vars/all/vault_cavalid.yml'],                                  'needs_vault': True},
    'vault_storage':          {'exe': 'ansible-vault',    'args': ['view', 'group_vars/all/vault_storage.yml'],                                  'needs_vault': True},
    'vault_pgadmin':          {'exe': 'ansible-vault',    'args': ['view', 'group_vars/all/vault_pgadmin.yml'],                                  'needs_vault': True},
    'vault_grafana':          {'exe': 'ansible-vault',    'args': ['view', 'group_vars/all/vault_grafana.yml'],                                  'needs_vault': True},
    'dryrun_all':             {'exe': 'ansible-playbook', 'args': ['site.yml',              '--check', '--diff'],                              'needs_vault': True},
    'dryrun_ca_valid':        {'exe': 'ansible-playbook', 'args': ['site.yml', '--tags', 'rancher_ca_valid', '--check', '--diff'],               'needs_vault': True},
    'dryrun_self':            {'exe': 'ansible-playbook', 'args': ['site-self-signed.yml',  '--check', '--diff'],                              'needs_vault': True},
    'dryrun_aks_static_pv':   {'exe': 'ansible-playbook', 'args': ['site.yml', '--tags', 'aks_static_pv',    '--check', '--diff'],               'needs_vault': True},
    'dryrun_pgadmin':         {'exe': 'ansible-playbook', 'args': ['site.yml', '--tags', 'pgadmin',          '--check', '--diff'],               'needs_vault': True},
    'dryrun_grafana':         {'exe': 'ansible-playbook', 'args': ['site.yml', '--tags', 'grafana',          '--check', '--diff'],               'needs_vault': True},
    'deploy_all':             {'exe': 'ansible-playbook', 'args': ['site.yml'],                                                                  'needs_vault': True},
    'deploy_ca_valid':        {'exe': 'ansible-playbook', 'args': ['site.yml', '--tags', 'rancher_ca_valid'],                                    'needs_vault': True},
    'deploy_self':            {'exe': 'ansible-playbook', 'args': ['site-self-signed.yml'],                                                      'needs_vault': True},
    'deploy_aks_static_pv':   {'exe': 'ansible-playbook', 'args': ['site.yml', '--tags', 'aks_static_pv'],                                       'needs_vault': True},
    'deploy_pgadmin':         {'exe': 'ansible-playbook', 'args': ['site.yml', '--tags', 'pgadmin'],                                             'needs_vault': True},
    'deploy_grafana':         {'exe': 'ansible-playbook', 'args': ['site.yml', '--tags', 'grafana'],                                             'needs_vault': True},
    'uninstall':              {'exe': 'bash',             'args': ['uninstall-rancher.sh'],                                                      'needs_vault': False},
    'uninstall_pgadmin':      {'exe': 'bash',             'args': ['uninstall-pgadmin.sh'],                                                      'needs_vault': False},
    'uninstall_grafana':      {'exe': 'bash',             'args': ['uninstall-grafana.sh'],                                                      'needs_vault': False},
}

# Nome PVC valido in Kubernetes: lowercase alfanumerici + '-' e '.'
# (RFC 1123 subdomain, 253 char max). Usato per validare i nomi PV passati
# dal client all'endpoint /api/disks/delete.
_K8S_NAME_RE = re.compile(r'^[a-z0-9]([a-z0-9.\-]{0,251}[a-z0-9])?$')


def _run(cmd_info, vault_password):
    vault_pass_file = None
    try:
        env = os.environ.copy()
        env['VIRTUAL_ENV'] = VENV
        env['PATH'] = f'{VENV}/bin:' + env.get('PATH', '')
        env.pop('PYTHONHOME', None)
        env['ANSIBLE_FORCE_COLOR'] = '1'
        env['PYTHONUNBUFFERED'] = '1'

        cmd_parts = [cmd_info['exe']] + list(cmd_info['args'])

        if vault_password:
            tf = tempfile.NamedTemporaryFile(mode='w', suffix='.vaultpass', delete=False)
            tf.write(vault_password)
            tf.close()
            vault_pass_file = tf.name
            cmd_parts += ['--vault-password-file', vault_pass_file]

        quoted = ' '.join(shlex.quote(p) for p in cmd_parts)
        shell_cmd = (
            f'source {VENV}/bin/activate'
            f' && printf "\\033[2m[venv] activated: %s\\n[venv] python:    %s\\033[0m\\n" "$VIRTUAL_ENV" "$(which python)"'
            f' && exec {quoted}'
        )

        proc = subprocess.Popen(
            ['bash', '-c', shell_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=ANSIBLE_DIR,
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
        if vault_pass_file:
            try:
                os.unlink(vault_pass_file)
            except OSError:
                pass
        _job_lock.release()


@app.route('/api/file')
def api_file():
    rel = request.args.get('path', '')
    full = os.path.normpath(os.path.join(ANSIBLE_DIR, rel))
    ansible_root = os.path.normpath(ANSIBLE_DIR)
    if full != ansible_root and not full.startswith(ansible_root + os.sep):
        return jsonify({'error': 'Path non consentito'}), 403
    try:
        with open(full, 'r', encoding='utf-8') as f:
            return jsonify({'content': f.read(), 'path': rel})
    except FileNotFoundError:
        return jsonify({'error': 'File non trovato'}), 404
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


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


@app.route('/api/run', methods=['POST'])
def api_run():
    data = request.get_json(force=True) or {}
    action = data.get('action', '')
    vault_password = data.get('vault_password', '')

    if action not in COMMANDS:
        return jsonify({'error': 'Azione non valida'}), 400

    cmd_info = COMMANDS[action]
    if cmd_info['needs_vault'] and not vault_password:
        return jsonify({'error': 'Vault password obbligatoria per questa operazione'}), 400

    if not _job_lock.acquire(blocking=False):
        return jsonify({'error': 'Un job è già in esecuzione. Attendi il completamento.'}), 409

    _job_state['output'] = []
    _job_state['status'] = 'running'

    t = threading.Thread(
        target=_run,
        args=(cmd_info, vault_password if cmd_info['needs_vault'] else None),
        daemon=True,
    )
    t.start()

    return jsonify({'status': 'started'})


def _kubectl_env():
    """Env per chiamate kubectl sincrone (con venv attivo per kubeconfig coerente)."""
    env = os.environ.copy()
    env['VIRTUAL_ENV'] = VENV
    env['PATH'] = f'{VENV}/bin:' + env.get('PATH', '')
    env.pop('PYTHONHOME', None)
    return env


# ---------------------------------------------------------------------------
# Inventario componenti dello stack (mappa 1:1 i role di site.yml).
# namespace/deployment sono i nomi reali creati dai role; 'ingress' (ns, name)
# serve a ricavare l'URL pubblico dall'Ingress effettivo nel cluster.
# ---------------------------------------------------------------------------
COMPONENTS = [
    {'key': 'traefik',      'name': 'Traefik',      'kind': 'Ingress Controller',
     'namespace': 'traefik',       'deployment': 'traefik',        'ingress': None},
    {'key': 'rancher',      'name': 'Rancher',      'kind': 'Platform',
     'namespace': 'cattle-system', 'deployment': 'rancher',        'ingress': ('cattle-system', 'rancher')},
    {'key': 'cert-manager', 'name': 'cert-manager', 'kind': 'TLS',
     'namespace': 'cert-manager',  'deployment': 'cert-manager',   'ingress': None},
    {'key': 'pgadmin',      'name': 'pgAdmin 4',    'kind': 'Application',
     'namespace': 'monitoring',    'deployment': 'pgadmin',        'ingress': ('monitoring', 'pgadmin')},
    {'key': 'grafana',      'name': 'Grafana 11',   'kind': 'Observability',
     'namespace': 'monitoring',    'deployment': 'grafana',        'ingress': ('monitoring', 'grafana')},
]


def _kubectl_json(kubectl, env, args, timeout=15):
    """Esegue 'kubectl <args>' attesi in JSON. Ritorna (data|None, error|None)."""
    try:
        r = subprocess.run(
            [kubectl] + args,
            capture_output=True, text=True, env=env, cwd=ANSIBLE_DIR, timeout=timeout,
        )
        if r.returncode != 0:
            return None, ((r.stderr or r.stdout) or '').strip()[:300]
        return json.loads(r.stdout or '{}'), None
    except subprocess.TimeoutExpired:
        return None, f'kubectl timeout >{timeout}s'
    except json.JSONDecodeError as exc:
        return None, f'output non JSON: {exc}'
    except Exception as exc:
        return None, str(exc)


def _image_tag(deploy):
    """Estrae il tag immagine del primo container (es. grafana/grafana:11.3.0 -> 11.3.0)."""
    try:
        containers = (((deploy.get('spec') or {}).get('template') or {})
                      .get('spec') or {}).get('containers') or []
        if not containers:
            return None
        image = containers[0].get('image', '')
        # separa il tag dall'eventuale registry:port/repo
        last = image.rsplit('/', 1)[-1]
        return last.split(':', 1)[1] if ':' in last else 'latest'
    except Exception:
        return None


def _collect_nodes(kubectl, env):
    """Stato dei nodi del cluster + versione Kubernetes (dal kubelet del primo nodo)."""
    data, err = _kubectl_json(kubectl, env, ['get', 'nodes', '-o', 'json'])
    items, ready, version = [], 0, None
    for n in (data or {}).get('items', []) or []:
        conds = (n.get('status') or {}).get('conditions', []) or []
        is_ready = any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in conds)
        if is_ready:
            ready += 1
        ni = (n.get('status') or {}).get('nodeInfo') or {}
        if not version:
            version = ni.get('kubeletVersion')
        items.append({
            'name': (n.get('metadata') or {}).get('name'),
            'ready': is_ready,
            'version': ni.get('kubeletVersion'),
        })
    return {'ready': ready, 'total': len(items), 'k8sVersion': version,
            'items': items, 'error': err}


def _collect_components(kubectl, env):
    """Stato di ogni componente dello stack a partire dai Deployment + Ingress reali."""
    deploys, derr = _kubectl_json(kubectl, env, ['get', 'deploy', '-A', '-o', 'json'])
    ingresses, ierr = _kubectl_json(kubectl, env, ['get', 'ingress', '-A', '-o', 'json'])

    dmap = {}
    for d in (deploys or {}).get('items', []) or []:
        m = d.get('metadata') or {}
        dmap[(m.get('namespace'), m.get('name'))] = d
    imap = {}
    for ing in (ingresses or {}).get('items', []) or []:
        m = ing.get('metadata') or {}
        imap[(m.get('namespace'), m.get('name'))] = ing

    out = []
    for c in COMPONENTS:
        comp = {'key': c['key'], 'name': c['name'], 'kind': c['kind'],
                'namespace': c['namespace'], 'installed': False,
                'version': None, 'ready': 0, 'desired': 0,
                'status': 'absent', 'url': None}
        d = dmap.get((c['namespace'], c['deployment']))
        if d:
            spec = d.get('spec') or {}
            st = d.get('status') or {}
            desired = spec.get('replicas', 0) or 0
            ready = st.get('readyReplicas', 0) or 0
            comp.update({
                'installed': True,
                'desired': desired,
                'ready': ready,
                'version': _image_tag(d),
                'status': 'healthy' if (desired > 0 and ready == desired)
                          else ('degraded' if ready > 0 else 'down'),
            })
        if c.get('ingress'):
            ing = imap.get(c['ingress'])
            rules = ((ing or {}).get('spec') or {}).get('rules') or []
            if rules and rules[0].get('host'):
                comp['url'] = 'https://' + rules[0]['host']
        out.append(comp)
    return out, (derr or ierr)


@app.route('/api/health')
def api_health():
    """Riepilogo salute cluster per la home: nodi, versione K8s, conteggio componenti."""
    kubectl = shutil.which('kubectl') or 'kubectl'
    env = _kubectl_env()
    nodes = _collect_nodes(kubectl, env)
    comps, cerr = _collect_components(kubectl, env)
    healthy = sum(1 for c in comps if c['status'] == 'healthy')
    return jsonify({
        'nodes': {'ready': nodes['ready'], 'total': nodes['total']},
        'k8sVersion': nodes['k8sVersion'],
        'rancher': next((c for c in comps if c['key'] == 'rancher'), None),
        'components': {
            'healthy': healthy,
            'total': len(comps),
            'items': [{'key': c['key'], 'name': c['name'], 'status': c['status']} for c in comps],
        },
        'error': nodes.get('error') or cerr,
    })


@app.route('/api/stack')
def api_stack():
    """Inventario dettagliato dei componenti dello stack (pagina Stack)."""
    kubectl = shutil.which('kubectl') or 'kubectl'
    env = _kubectl_env()
    comps, err = _collect_components(kubectl, env)
    return jsonify({'components': comps, 'error': err})


# Secret TLS che espone la console Rancher (creato dal role CA-Valid dal vault,
# o dynamiclistener in self-signed). Solo metadati pubblici del certificato.
RANCHER_TLS_SECRET = 'tls-rancher-ingress'
RANCHER_TLS_NS = 'cattle-system'


def _parse_dn(dn):
    """Parsa un Distinguished Name openssl ('CN = x, O = y' o '/CN=x/O=y') in dict."""
    out = {}
    for part in re.split(r'[,/]', dn or ''):
        if '=' in part:
            k, v = part.split('=', 1)
            out[k.strip().upper()] = v.strip()
    return out


def _parse_openssl_date(s):
    """Converte 'Jul 31 23:59:59 2027 GMT' in datetime UTC (None se non parsabile)."""
    s = ' '.join((s or '').replace('GMT', '').split())
    try:
        return datetime.strptime(s, '%b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@app.route('/api/cert')
def api_cert():
    """Metadati del certificato TLS che espone la console Rancher: issuer, date di
    emissione/scadenza, FQDN (CN) e SAN. Legge il Secret tls-rancher-ingress e
    parsa SOLO il leaf con openssl (nessuna chiave privata viene mai esposta)."""
    kubectl = shutil.which('kubectl') or 'kubectl'
    env = _kubectl_env()
    base = {'found': False, 'secret': RANCHER_TLS_SECRET, 'namespace': RANCHER_TLS_NS, 'error': None}

    code, out = _kubectl(kubectl, env, [
        'get', 'secret', RANCHER_TLS_SECRET, '-n', RANCHER_TLS_NS,
        '-o', 'jsonpath={.data.tls\\.crt}',
    ])
    if code != 0 or not out.strip():
        base['error'] = (out.strip()[:200] or f'secret {RANCHER_TLS_SECRET} non trovato')
        return jsonify(base)

    try:
        pem = base64.b64decode(out.strip())
    except Exception as exc:
        base['error'] = f'base64 decode: {exc}'
        return jsonify(base)

    openssl = shutil.which('openssl') or 'openssl'

    def _run_openssl(args):
        try:
            r = subprocess.run([openssl, 'x509', '-noout'] + args,
                               input=pem, capture_output=True, timeout=10)
            return r.returncode, (r.stdout or b'').decode('utf-8', 'replace'), \
                   (r.stderr or b'').decode('utf-8', 'replace')
        except Exception as exc:
            return -1, '', str(exc)

    # Campi base (sempre supportati). Il leaf e' il primo cert del fullchain.
    rc, txt, errtxt = _run_openssl(['-issuer', '-subject', '-startdate', '-enddate'])
    if rc != 0:
        base['error'] = (errtxt.strip()[:200] or 'openssl x509 fallito')
        return jsonify(base)

    info = dict(base)
    info['found'] = True
    issuer = subject = None
    not_after_dt = None
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith('issuer='):
            issuer = line[len('issuer='):].strip()
        elif line.startswith('subject='):
            subject = line[len('subject='):].strip()
        elif line.startswith('notBefore='):
            dt = _parse_openssl_date(line[len('notBefore='):])
            info['notBefore'] = dt.isoformat().replace('+00:00', 'Z') if dt else None
        elif line.startswith('notAfter='):
            not_after_dt = _parse_openssl_date(line[len('notAfter='):])
            info['notAfter'] = not_after_dt.isoformat().replace('+00:00', 'Z') if not_after_dt else None

    # SAN (best-effort: -ext richiede openssl >= 1.1.1; se manca non e' fatale).
    sans = []
    rc2, txt2, _ = _run_openssl(['-ext', 'subjectAltName'])
    if rc2 == 0:
        for line in txt2.splitlines():
            if 'DNS:' in line:
                sans = [p.strip()[4:] for p in line.split(',') if p.strip().startswith('DNS:')]

    issuer_dn = _parse_dn(issuer)
    subject_dn = _parse_dn(subject)
    info['issuer'] = issuer
    info['subject'] = subject
    info['issuerCN'] = issuer_dn.get('CN')
    info['issuerO'] = issuer_dn.get('O')
    info['subjectCN'] = subject_dn.get('CN')
    info['fqdn'] = subject_dn.get('CN')
    info['sans'] = sans
    info['selfSigned'] = bool(
        (issuer and subject and issuer == subject)
        or 'dynamiclistener' in (issuer or '').lower()
    )
    if not_after_dt:
        info['daysRemaining'] = (not_after_dt - datetime.now(timezone.utc)).days
    return jsonify(info)


@app.route('/api/cluster')
def api_cluster():
    """Nome del cluster corrente = kubectl config current-context.
    Usato dalla GUI per mostrare il cluster reale su cui si opera, al posto
    del vecchio placeholder hardcoded. Read-only, veloce."""
    kubectl = shutil.which('kubectl') or 'kubectl'
    try:
        result = subprocess.run(
            [kubectl, 'config', 'current-context'],
            capture_output=True, text=True, env=_kubectl_env(),
            cwd=ANSIBLE_DIR, timeout=10,
        )
        if result.returncode != 0:
            return jsonify({'context': None,
                            'error': (result.stderr or result.stdout).strip()[:200]})
        return jsonify({'context': result.stdout.strip()})
    except subprocess.TimeoutExpired:
        return jsonify({'context': None, 'error': 'kubectl timeout (>10s)'})
    except Exception as exc:
        return jsonify({'context': None, 'error': str(exc)})


@app.route('/api/disks/list')
def api_disks_list():
    """Lista i PersistentVolume del cluster con metadati Azure Disk."""
    kubectl = shutil.which('kubectl') or 'kubectl'
    try:
        result = subprocess.run(
            [kubectl, 'get', 'pv', '-o', 'json'],
            capture_output=True, text=True, env=_kubectl_env(),
            cwd=ANSIBLE_DIR, timeout=15,
        )
        if result.returncode != 0:
            return jsonify({
                'error': 'kubectl get pv ha fallito',
                'detail': (result.stderr or result.stdout).strip()[:500],
            }), 502
        data = json.loads(result.stdout or '{}')
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'kubectl timeout (>15s)'}), 504
    except json.JSONDecodeError as exc:
        return jsonify({'error': f'output kubectl non JSON: {exc}'}), 502
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500

    items = []
    for pv in data.get('items', []) or []:
        meta = pv.get('metadata') or {}
        spec = pv.get('spec') or {}
        status = pv.get('status') or {}
        csi = spec.get('csi') or {}
        claim = spec.get('claimRef') or {}
        bound_pvc = None
        if claim.get('name'):
            bound_pvc = f"{claim.get('namespace') or '-'}/{claim.get('name')}"
        items.append({
            'name': meta.get('name'),
            'capacity': (spec.get('capacity') or {}).get('storage'),
            'accessModes': spec.get('accessModes') or [],
            'reclaimPolicy': spec.get('persistentVolumeReclaimPolicy'),
            'storageClass': spec.get('storageClassName') or '',
            'status': status.get('phase'),
            'boundPVC': bound_pvc,
            'csiDriver': csi.get('driver'),
            'volumeHandle': csi.get('volumeHandle'),
        })
    # Ordine stabile: prima i Released (sicuri da cancellare), poi Available,
    # poi Bound (rischiosi). All'interno: ordine alfabetico.
    phase_rank = {'Released': 0, 'Available': 1, 'Bound': 2}
    items.sort(key=lambda x: (phase_rank.get(x.get('status') or '', 9), x.get('name') or ''))
    return jsonify({'items': items, 'count': len(items)})


def _kubectl(kubectl, env, args, timeout=15):
    """Esegue 'kubectl <args>' e ritorna (returncode, output_combinato_stripped)."""
    try:
        r = subprocess.run(
            [kubectl] + args,
            capture_output=True, text=True, env=env, cwd=ANSIBLE_DIR, timeout=timeout,
        )
        return r.returncode, ((r.stdout or '') + (r.stderr or '')).strip()
    except subprocess.TimeoutExpired:
        return -1, f'(kubectl timeout >{timeout}s)'
    except Exception as exc:
        return -2, str(exc)


def _delete_pv_robust(kubectl, env, name):
    """Cancella un PV in modo idempotente, forzando la rimozione dei finalizer
    se il PV resta stuck in Terminating. Casi tipici di stuck su Azure Disk:
      - kubernetes.io/pv-protection: PVC ancora presente
      - external-attacher/disk.csi.azure.com: volume ancora attached al nodo
      - external-provisioner/disk.csi.azure.com: AKS non riesce a deprovisionare
    Strategia: delete --wait=false -> poll 8s -> patch finalizers null -> poll 10s.
    """
    log_lines = []

    def pv_exists():
        c, o = _kubectl(kubectl, env,
                        ['get', 'pv', name, '--ignore-not-found',
                         '-o', 'jsonpath={.metadata.name}'])
        return c == 0 and o != ''

    # 1) Delete non-bloccante (l'API server accetta la richiesta e ritorna subito).
    code, out = _kubectl(kubectl, env,
                         ['delete', 'pv', name, '--ignore-not-found', '--wait=false'])
    if out:
        log_lines.append(out)
    if code != 0 and 'not found' not in out.lower():
        return {'name': name, 'ok': False, 'output': '\n'.join(log_lines)}

    # 2) Polling: aspetta fino a 8s che il PV sparisca da solo.
    for _ in range(4):
        time.sleep(2)
        if not pv_exists():
            return {'name': name, 'ok': True,
                    'output': '\n'.join(log_lines) or 'PV cancellato'}

    # 3) Ancora presente -> rimozione forzata dei finalizer (stesso pattern
    #    di uninstall-rancher.sh per i namespace stuck in Terminating).
    log_lines.append('PV stuck in Terminating, forzo rimozione finalizer')
    code, out = _kubectl(kubectl, env,
                         ['patch', 'pv', name, '--type=merge',
                          '-p', '{"metadata":{"finalizers":null}}'])
    if out:
        log_lines.append(out)

    # 4) Verifica finale (fino a 10s).
    for _ in range(5):
        time.sleep(2)
        if not pv_exists():
            return {'name': name, 'ok': True, 'output': '\n'.join(log_lines)}

    log_lines.append('PV ancora presente dopo rimozione finalizer (anomalo: '
                     'verifica con: kubectl get pv ' + name + ' -o yaml)')
    return {'name': name, 'ok': False, 'output': '\n'.join(log_lines)}


@app.route('/api/disks/delete', methods=['POST'])
def api_disks_delete():
    """Cancella i PersistentVolume selezionati (uno alla volta, riporta esito per nome).
    Usa _delete_pv_robust che gestisce i finalizer stuck (caso comune sui PV CSI
    Azure quando il PVC esiste ancora o il volume e' attached a un nodo)."""
    payload = request.get_json(force=True, silent=True) or {}
    names = payload.get('names')
    if not isinstance(names, list) or not names:
        return jsonify({'error': "Campo 'names' deve essere una lista non vuota"}), 400

    invalid = [n for n in names if not (isinstance(n, str) and _K8S_NAME_RE.match(n))]
    if invalid:
        return jsonify({'error': f'Nomi PV non validi: {invalid}'}), 400

    kubectl = shutil.which('kubectl') or 'kubectl'
    env = _kubectl_env()
    results = [_delete_pv_robust(kubectl, env, name) for name in names]
    return jsonify({'results': results})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=False, threaded=True)
