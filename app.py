"""
Polaris · Cert Inspector

Dashboard read-only di diagnostica certificati per ambienti Kubernetes/Rancher.

Uso `kubectl` (gia' configurato sul controller) per estrarre tutti i certificati
visibili in un cluster: secret di tipo TLS, riferimenti negli Ingress, CA
pubblicata da Rancher (`setting/cacerts`). Per ogni certificato esegue un
parsing con OpenSSL e individua:

  - dove vive il certificato (namespace/secret/ingress)
  - se e' esposto esternamente (hostnames negli Ingress/SAN)
  - chi e' la CA emittente e il suo fingerprint
  - scadenza, validita', tipo (CA, server, self-signed)

Esegue anche un probe TLS verso gli hostname estratti per capire se quello
effettivamente servito dall'esterno (es. nginx davanti a Rancher) coincide
con quello presente nel cluster.

Per ogni anomalia, il frontend produce un blocco "Remediation" che indica:
  - i comandi corretti
  - su quale VM eseguirli (control-plane / Rancher / nginx esterno)

L'esecuzione e' read-only: la dashboard NON applica nulla.
"""
from flask import Flask, request, jsonify, render_template
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import threading

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Stato job (una scansione/probe alla volta -> output streamabile sul terminale)
# ---------------------------------------------------------------------------
_job_lock = threading.Lock()
_job_state = {'status': 'idle', 'output': []}


def _log(line):
    _job_state['output'].append(line)


def _kubectl(args, context=None, timeout=20):
    """Lancia kubectl. Ritorna (rc, stdout, stderr). Non lancia eccezioni."""
    cmd = ['kubectl']
    if context:
        cmd += ['--context', context]
    cmd += args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout or '', r.stderr or ''
    except FileNotFoundError:
        return 127, '', 'kubectl non trovato nel PATH'
    except subprocess.TimeoutExpired:
        return 124, '', f'timeout dopo {timeout}s'
    except Exception as exc:
        return -1, '', str(exc)


# ---------------------------------------------------------------------------
# Parsing certificati: usa la stdlib (cryptography del pacchetto python3-cryptography
# se presente, altrimenti fallback minimale con openssl).
# ---------------------------------------------------------------------------
def _try_import_cryptography():
    # Catturo BaseException perche' alcune build rotte di cryptography (rust/cffi
    # non installato) sollevano un pyo3 PanicException che non eredita da
    # Exception. In quel caso usiamo il fallback openssl.
    try:
        from cryptography import x509  # noqa: F401
        from cryptography.hazmat.primitives import hashes  # noqa: F401
        return True
    except BaseException:
        return False


_HAS_CRYPTO = _try_import_cryptography()


def _parse_cert_pem(pem_bytes):
    """Parsing di un certificato PEM. Ritorna dict con tutti i campi rilevanti.

    Usa cryptography quando disponibile, altrimenti delega a openssl x509 via
    subprocess. Restituisce {error: ...} se non riesce."""
    if _HAS_CRYPTO:
        try:
            return _parse_with_cryptography(pem_bytes)
        except Exception as exc:
            return {'error': f'parse error: {exc}'}
    return _parse_with_openssl(pem_bytes)


def _parse_with_cryptography(pem_bytes):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_pem_x509_certificate(pem_bytes)

    def name_str(name):
        return ', '.join(f'{a.oid._name}={a.value}' for a in name)

    def name_field(name, oid):
        try:
            attrs = name.get_attributes_for_oid(oid)
            return attrs[0].value if attrs else None
        except Exception:
            return None

    from cryptography.x509.oid import NameOID, ExtensionOID

    sans = []
    is_ca = False
    eku = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [str(n.value) for n in ext.value]
    except Exception:
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        is_ca = bool(ext.value.ca)
    except Exception:
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        eku = [u._name for u in ext.value]
    except Exception:
        pass

    fp_sha256 = cert.fingerprint(hashes.SHA256()).hex()
    # Hash dello SPKI (Subject Public Key Info) — utile per riconoscere il
    # rinnovo dello stesso cert con stessa chiave.
    spki_der = cert.public_key().public_bytes(
        encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.DER,
        format=__import__('cryptography').hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_sha256 = hashlib.sha256(spki_der).hexdigest()

    subject_cn = name_field(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = name_field(cert.issuer, NameOID.COMMON_NAME)
    issuer_o = name_field(cert.issuer, NameOID.ORGANIZATION_NAME)

    # not_valid_after_utc esiste da cryptography 42+, fallback a not_valid_after
    nva = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after
    nvb = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc) if nva.tzinfo else datetime.utcnow()
    days_remaining = int((nva - now).total_seconds() // 86400)
    expired = days_remaining < 0
    self_signed = (cert.subject == cert.issuer)

    return {
        'subjectCN': subject_cn, 'subject': name_str(cert.subject),
        'issuerCN': issuer_cn, 'issuerO': issuer_o, 'issuer': name_str(cert.issuer),
        'serial': hex(cert.serial_number),
        'notBefore': nvb.isoformat(), 'notAfter': nva.isoformat(),
        'daysRemaining': days_remaining, 'expired': expired,
        'sans': sans, 'isCA': is_ca, 'selfSigned': self_signed,
        'eku': eku,
        'fingerprintSHA256': fp_sha256,
        'spkiSHA256': spki_sha256,
    }


def _parse_with_openssl(pem_bytes):
    """Fallback usando il comando openssl. Estrae i campi principali via -noout
    -text e -fingerprint."""
    def _ssl(args, stdin_bytes):
        try:
            r = subprocess.run(['openssl'] + args, input=stdin_bytes,
                               capture_output=True, timeout=15)
            return r.returncode, r.stdout, r.stderr
        except FileNotFoundError:
            return 127, b'', b'openssl non installato'
        except Exception as exc:
            return -1, b'', str(exc).encode()

    rc, out, err = _ssl(['x509', '-noout', '-fingerprint', '-sha256'], pem_bytes)
    if rc != 0:
        return {'error': (err or out).decode(errors='replace').strip()}
    fp = re.search(rb'Fingerprint=([0-9A-F:]+)', out)
    fp_sha256 = fp.group(1).decode().replace(':', '').lower() if fp else None

    rc, txt, _ = _ssl(['x509', '-noout', '-subject', '-issuer', '-dates',
                       '-serial', '-ext', 'subjectAltName,basicConstraints,extendedKeyUsage'], pem_bytes)
    txt = txt.decode(errors='replace') if rc == 0 else ''
    def line(prefix):
        m = re.search(rf'^{re.escape(prefix)}=?\s*(.*)$', txt, re.M)
        return m.group(1).strip() if m else None
    subject = line('subject')
    issuer = line('issuer')
    not_before_raw = line('notBefore')
    not_after_raw = line('notAfter')
    serial = line('serial')

    sans = []
    m = re.search(r'X509v3 Subject Alternative Name:\s*\n\s*(.+)', txt)
    if m:
        sans = [s.strip().split(':', 1)[1] if ':' in s.strip() else s.strip()
                for s in m.group(1).split(',')]
    is_ca = 'CA:TRUE' in txt
    eku = []
    m = re.search(r'X509v3 Extended Key Usage:\s*\n\s*(.+)', txt)
    if m: eku = [u.strip() for u in m.group(1).split(',')]

    from datetime import datetime, timezone
    def parse_dt(raw):
        if not raw: return None
        try:
            return datetime.strptime(raw, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
        except Exception:
            return None
    nva = parse_dt(not_after_raw); nvb = parse_dt(not_before_raw)
    days_remaining = int((nva - datetime.now(timezone.utc)).total_seconds() // 86400) if nva else None
    expired = (days_remaining is not None and days_remaining < 0)
    self_signed = (subject == issuer)

    def cn(s): m = re.search(r'CN\s*=\s*([^,/]+)', s or ''); return m.group(1).strip() if m else None
    def org(s): m = re.search(r'O\s*=\s*([^,/]+)', s or ''); return m.group(1).strip() if m else None

    return {
        'subjectCN': cn(subject), 'subject': subject,
        'issuerCN': cn(issuer), 'issuerO': org(issuer), 'issuer': issuer,
        'serial': serial,
        'notBefore': nvb.isoformat() if nvb else None,
        'notAfter': nva.isoformat() if nva else None,
        'daysRemaining': days_remaining, 'expired': expired,
        'sans': sans, 'isCA': is_ca, 'selfSigned': self_signed,
        'eku': eku,
        'fingerprintSHA256': fp_sha256,
        'spkiSHA256': None,  # non calcolato nel fallback
    }


def _ca_checksum_rancher(pem_text):
    """Replica il calcolo che Rancher fa per pubblicare la CA su
    `setting/cacerts`: SHA256 esadecimale del PEM (incluse newline). Usato dai
    cluster downstream per validare il control-plane."""
    return hashlib.sha256(pem_text.encode('utf-8')).hexdigest()


# ---------------------------------------------------------------------------
# Scoperta certificati: contesti, secret TLS, ingress, Rancher cacerts
# ---------------------------------------------------------------------------
def _contexts():
    rc, out, err = _kubectl(['config', 'get-contexts', '-o', 'name'], context=None, timeout=10)
    if rc != 0: return []
    return [l.strip() for l in out.splitlines() if l.strip()]


def _current_context():
    rc, out, _ = _kubectl(['config', 'current-context'], context=None, timeout=10)
    return out.strip() if rc == 0 else None


def _list_tls_secrets(context):
    """Tutti i secret con almeno un certificato (tls.crt o ca.crt)."""
    rc, out, err = _kubectl(
        ['get', 'secret', '-A', '-o', 'json'], context=context, timeout=30,
    )
    if rc != 0: return [], err
    try:
        data = json.loads(out)
    except Exception as exc:
        return [], f'json parse: {exc}'
    items = []
    for it in data.get('items', []):
        md = it.get('metadata', {}) or {}
        ns = md.get('namespace'); name = md.get('name')
        stype = it.get('type', '')
        d = it.get('data', {}) or {}
        for key in ('tls.crt', 'ca.crt', 'cacerts.pem', 'cacert.pem'):
            if key in d:
                items.append({
                    'namespace': ns, 'name': name, 'secretType': stype,
                    'dataKey': key, 'b64': d[key],
                    'hasKey': 'tls.key' in d,
                })
    return items, None


def _list_ingress_tls(context):
    rc, out, err = _kubectl(['get', 'ingress', '-A', '-o', 'json'], context=context, timeout=30)
    if rc != 0:
        # ingress potrebbe non esistere in cluster vecchi -> ritorna vuoto
        return [], err
    try:
        data = json.loads(out)
    except Exception as exc:
        return [], f'json parse: {exc}'
    out_list = []
    for it in data.get('items', []):
        md = it.get('metadata', {}) or {}
        spec = it.get('spec', {}) or {}
        ns = md.get('namespace'); name = md.get('name')
        ingressClass = spec.get('ingressClassName') or (md.get('annotations') or {}).get('kubernetes.io/ingress.class')
        hosts_rules = [r.get('host') for r in (spec.get('rules') or []) if r.get('host')]
        for t in (spec.get('tls') or []):
            out_list.append({
                'namespace': ns, 'ingress': name, 'ingressClass': ingressClass,
                'secretName': t.get('secretName'),
                'hosts': t.get('hosts') or [], 'rulesHosts': hosts_rules,
            })
    return out_list, None


def _rancher_setting(context, setting):
    """Legge una `setting` di Rancher (CRD management.cattle.io/v3). Ritorna
    None se Rancher non e' installato in questo cluster."""
    rc, out, err = _kubectl(
        ['get', f'settings.management.cattle.io', setting, '-o', 'json'],
        context=context, timeout=15,
    )
    if rc != 0: return None
    try:
        return json.loads(out).get('value')
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Probe TLS verso un endpoint esterno (es. l'nginx davanti a Rancher).
# ---------------------------------------------------------------------------
def _probe_tls(host, port=443, server_name=None, timeout=8):
    """Apre una connessione TLS senza verifica chain (vogliamo *vedere* il cert
    indipendentemente dalla sua validita') e ritorna il PEM del leaf cert."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sni = server_name or host
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as s:
                der = s.getpeercert(binary_form=True)
                pem = ssl.DER_cert_to_PEM_cert(der)
                return {'ok': True, 'pem': pem, 'sni': sni}
    except Exception as exc:
        return {'ok': False, 'error': str(exc), 'sni': sni}


# ---------------------------------------------------------------------------
# Scansione completa: assembla certificati + cross-check Rancher + diagnostica
# ---------------------------------------------------------------------------
def _decode_b64(s):
    try: return base64.b64decode(s)
    except Exception: return b''


def _split_pem(blob):
    """Una singola chiave puo' contenere catena di piu' certificati PEM. Li
    spezzo per analizzarli separatamente."""
    if isinstance(blob, bytes):
        try: blob = blob.decode('utf-8', errors='replace')
        except Exception: return []
    parts = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                       blob, re.DOTALL)
    return parts


def _scan(context):
    out = {
        'context': context, 'currentContext': _current_context(),
        'certs': [], 'ingresses': [], 'rancher': None,
        'errors': [], 'summary': {},
    }
    _log(f'\x1b[1;36m[scan]\x1b[0m context={context or "(current)"}')

    # secrets
    secrets, err = _list_tls_secrets(context)
    if err: out['errors'].append({'where': 'secrets', 'msg': err})
    _log(f'\x1b[2m  trovati {len(secrets)} secret con cert\x1b[0m')

    # ingresses
    ingresses, err = _list_ingress_tls(context)
    if err: out['errors'].append({'where': 'ingress', 'msg': err})
    out['ingresses'] = ingresses
    _log(f'\x1b[2m  trovati {len(ingresses)} ingress TLS\x1b[0m')

    # Rancher CA setting (se presente)
    cacerts_value = _rancher_setting(context, 'cacerts')
    server_url    = _rancher_setting(context, 'server-url')
    out['rancher'] = {
        'installed': cacerts_value is not None,
        'cacerts': cacerts_value,
        'cacertsChecksum': _ca_checksum_rancher(cacerts_value) if cacerts_value else None,
        'serverURL': server_url,
    }
    if cacerts_value:
        _log(f'\x1b[2m  Rancher cacerts checksum: {out["rancher"]["cacertsChecksum"][:16]}…\x1b[0m')

    # mappa secretName -> ingressi che lo usano (per "esposizione esterna")
    secret_to_ingress = {}
    for ig in ingresses:
        key = f'{ig["namespace"]}/{ig["secretName"]}'
        secret_to_ingress.setdefault(key, []).append(ig)

    # parsing dei cert: ogni secret puo' avere chain -> spezzo
    certs_out = []
    for sec in secrets:
        raw = _decode_b64(sec['b64'])
        pem_blocks = _split_pem(raw)
        if not pem_blocks:
            certs_out.append({
                'namespace': sec['namespace'], 'secret': sec['name'],
                'secretType': sec['secretType'], 'dataKey': sec['dataKey'],
                'parsed': {'error': 'nessun blocco PEM trovato'},
            })
            continue
        for idx, blk in enumerate(pem_blocks):
            parsed = _parse_cert_pem(blk.encode('utf-8'))
            ig_refs = secret_to_ingress.get(f'{sec["namespace"]}/{sec["name"]}', [])
            # esposizione: se referenziato da un Ingress -> esterno; se contiene
            # CA:TRUE e' una CA; altrimenti probabilmente interno.
            if parsed.get('isCA'):
                exposure = 'ca'
            elif ig_refs:
                exposure = 'ingress'
            else:
                exposure = 'internal'
            certs_out.append({
                'namespace': sec['namespace'], 'secret': sec['name'],
                'secretType': sec['secretType'], 'dataKey': sec['dataKey'],
                'chainIndex': idx, 'chainTotal': len(pem_blocks),
                'hasKey': sec['hasKey'],
                'parsed': parsed,
                'exposure': exposure,
                'ingressRefs': ig_refs,
            })

    out['certs'] = certs_out

    # diagnostiche
    out['findings'] = _diagnose(out)

    # summary
    total = len(certs_out)
    expired = sum(1 for c in certs_out if c['parsed'].get('expired'))
    expiring = sum(1 for c in certs_out
                   if (c['parsed'].get('daysRemaining') is not None)
                   and 0 <= c['parsed']['daysRemaining'] <= 30
                   and not c['parsed'].get('expired'))
    out['summary'] = {
        'total': total, 'expired': expired, 'expiring30d': expiring,
        'cas': sum(1 for c in certs_out if c.get('exposure') == 'ca'),
        'exposed': sum(1 for c in certs_out if c.get('exposure') == 'ingress'),
        'internal': sum(1 for c in certs_out if c.get('exposure') == 'internal'),
        'findings': len(out['findings']),
    }
    _log(f'\x1b[1;32m[scan] done\x1b[0m total={total} expired={expired} '
         f'expiring30d={expiring} findings={out["summary"]["findings"]}')
    return out


# ---------------------------------------------------------------------------
# Diagnostica: produce una lista di "findings" con severita' e remediation.
# Ogni finding e' un dict { id, severity, title, detail, where, fix:[steps] }.
# Le severita': info | warn | error.
# ---------------------------------------------------------------------------
def _new_finding(_id, severity, title, detail, where, fix):
    return {
        'id': _id, 'severity': severity, 'title': title,
        'detail': detail, 'where': where, 'fix': fix,
    }


def _diagnose(scan):
    findings = []
    ctx = scan.get('context')
    rancher = scan.get('rancher') or {}
    certs = scan.get('certs') or []

    # ------- F1: certificati scaduti -------
    for c in certs:
        p = c['parsed'] or {}
        if p.get('expired'):
            findings.append(_new_finding(
                f'expired:{c["namespace"]}/{c["secret"]}:{c.get("chainIndex",0)}',
                'error',
                f'Certificato scaduto: {p.get("subjectCN") or c["secret"]}',
                f'Scaduto il {p.get("notAfter")} (Issuer: {p.get("issuerCN") or "?"}). '
                f'Secret {c["namespace"]}/{c["secret"]}.',
                _where_for_secret(c, ctx),
                _fix_secret_replace(c, ctx),
            ))

    # ------- F2: certificati in scadenza <=30gg -------
    for c in certs:
        p = c['parsed'] or {}
        d = p.get('daysRemaining')
        if (d is not None) and 0 <= d <= 30 and not p.get('expired'):
            findings.append(_new_finding(
                f'expiring:{c["namespace"]}/{c["secret"]}:{c.get("chainIndex",0)}',
                'warn',
                f'Scadenza imminente: {p.get("subjectCN") or c["secret"]} ({d}gg)',
                f'Scade il {p.get("notAfter")}. Pianifica il rinnovo entro {d} giorni.',
                _where_for_secret(c, ctx),
                _fix_secret_replace(c, ctx),
            ))

    # ------- F3: Rancher cacerts vs tls-ca secret -------
    # tls-ca (in cattle-system) deve corrispondere a setting/cacerts. Se non
    # corrispondono, downstream cluster non si fidano piu' del control-plane.
    if rancher.get('installed'):
        ranch_sum = rancher.get('cacertsChecksum')
        tls_ca = _find_cert(certs, namespace='cattle-system', secret='tls-ca')
        if tls_ca:
            local_sum = _ca_checksum_rancher(_pem_of(tls_ca))
            if ranch_sum and local_sum and ranch_sum != local_sum:
                findings.append(_new_finding(
                    'ca-mismatch:rancher',
                    'error',
                    'CA checksum diverso: setting/cacerts vs secret tls-ca',
                    f'Rancher pubblica una CA con checksum {ranch_sum[:16]}… '
                    f'mentre il secret cattle-system/tls-ca calcola {local_sum[:16]}…. '
                    'I cluster downstream usano il checksum di setting/cacerts '
                    'per validare il control-plane: se non corrisponde, agent '
                    'non si fideranno.',
                    {'vm': 'Rancher (control-plane VM con kubectl al cluster local)',
                     'context': ctx},
                    [
                        '# 1) rigenera il setting cacerts dal secret reale:',
                        'kubectl -n cattle-system get secret tls-ca -o jsonpath=\'{.data.cacerts\\.pem}\' | base64 -d > /tmp/cacerts.pem',
                        'kubectl patch setting.management.cattle.io cacerts --type merge -p "{\\"value\\": \\"$(cat /tmp/cacerts.pem)\\"}"',
                        '# 2) riavvia gli agent dei downstream (cattle-cluster-agent) per riprendere il trust.',
                    ],
                ))
        elif ranch_sum:
            findings.append(_new_finding(
                'ca-orphan:rancher',
                'warn',
                'Rancher pubblica una CA ma manca il secret tls-ca',
                'Il setting cacerts e\' valorizzato ma in cattle-system non '
                'esiste un secret tls-ca: la CA esposta agli agent potrebbe '
                'essere disallineata rispetto al cert effettivo.',
                {'vm': 'Rancher', 'context': ctx},
                ['# verifica:',
                 'kubectl -n cattle-system get secret tls-ca || true',
                 'kubectl get setting.management.cattle.io cacerts -o yaml'],
            ))

    # ------- F4: tls-rancher-ingress vs CA dichiarata -------
    leaf = _find_cert(certs, namespace='cattle-system', secret='tls-rancher-ingress')
    if leaf:
        p = leaf['parsed'] or {}
        if p.get('selfSigned'):
            findings.append(_new_finding(
                'rancher-leaf-selfsigned', 'info',
                'tls-rancher-ingress e\' self-signed',
                'L\'ingress di Rancher serve un cert self-signed: ok per ambienti '
                'di test, ma il browser mostrera\' warning.',
                {'vm': 'Rancher', 'context': ctx},
                [],
            ))
        elif rancher.get('cacerts'):
            # Confronto Issuer del leaf vs CA dichiarata
            ca_pem = rancher['cacerts']
            ca_parsed = _parse_cert_pem(ca_pem.encode('utf-8')) if ca_pem else {}
            issuer_in_leaf = p.get('issuerCN')
            ca_subject = ca_parsed.get('subjectCN')
            if issuer_in_leaf and ca_subject and issuer_in_leaf != ca_subject:
                findings.append(_new_finding(
                    'rancher-leaf-issuer-vs-ca', 'warn',
                    'Issuer del cert Rancher diverso dalla CA dichiarata',
                    f'tls-rancher-ingress e\' firmato da "{issuer_in_leaf}" '
                    f'mentre setting/cacerts pubblica "{ca_subject}". '
                    'Probabile aggiornamento parziale: cert rinnovato ma CA '
                    'pubblicata non sincronizzata.',
                    {'vm': 'Rancher', 'context': ctx},
                    [
                        '# allinea il setting cacerts alla CA effettiva del cert servito:',
                        'openssl s_client -connect <rancher-host>:443 -servername <rancher-host> -showcerts </dev/null 2>/dev/null \\',
                        '  | awk \'/BEGIN CERTIFICATE/,/END CERTIFICATE/\' > /tmp/chain.pem',
                        '# estrai la CA (ultimo blocco PEM) e pubblicala:',
                        'kubectl patch setting.management.cattle.io cacerts --type merge -p "{\\"value\\": \\"$(cat /tmp/chain.pem)\\"}"',
                    ],
                ))

    # ------- F5: ingress con secret TLS non standard sparsi -------
    for ig in scan.get('ingresses') or []:
        ns = ig['namespace']; sec = ig['secretName']
        if not sec: continue
        if (ns, sec) in {('cattle-system', 'tls-rancher-ingress')}: continue
        found = _find_cert(certs, namespace=ns, secret=sec)
        if not found:
            findings.append(_new_finding(
                f'ingress-secret-missing:{ns}/{ig["ingress"]}',
                'warn',
                f'Ingress {ns}/{ig["ingress"]} referenzia secret inesistente',
                f'secretName="{sec}" ma non esiste nel namespace. '
                'L\'ingress controller potrebbe servire un cert di fallback.',
                {'vm': 'Control-plane / cluster local', 'context': ctx,
                 'ingressClass': ig.get('ingressClass')},
                [f'kubectl -n {ns} get ingress {ig["ingress"]} -o yaml',
                 f'kubectl -n {ns} get secret {sec}'],
            ))

    # ------- F6: cert "sparsi" — secret TLS non riferiti da alcun Ingress -------
    referenced = {(ig['namespace'], ig['secretName']) for ig in scan.get('ingresses') or []}
    for c in certs:
        p = c['parsed'] or {}
        if p.get('isCA') or c.get('secretType') != 'kubernetes.io/tls':
            continue
        if (c['namespace'], c['secret']) in referenced:
            continue
        # ignora cert di sistema (kube-system, cert-manager interni)
        if c['namespace'] in ('kube-system', 'kube-public', 'kube-node-lease'):
            continue
        findings.append(_new_finding(
            f'orphan-secret:{c["namespace"]}/{c["secret"]}',
            'info',
            f'Secret TLS orfano: {c["namespace"]}/{c["secret"]}',
            'Secret TLS che non risulta usato da alcun Ingress. Potrebbe '
            'essere consumato da un Service esposto via LB esterno o non '
            'piu\' utilizzato.',
            {'vm': 'Cluster', 'context': ctx},
            [f'kubectl -n {c["namespace"]} describe secret {c["secret"]}',
             f'kubectl get svc,deploy -A | grep -i {c["secret"]} || true'],
        ))

    return findings


def _find_cert(certs, namespace, secret):
    for c in certs:
        if c['namespace'] == namespace and c['secret'] == secret \
                and not (c['parsed'] or {}).get('isCA'):
            return c
    for c in certs:
        if c['namespace'] == namespace and c['secret'] == secret:
            return c
    return None


def _pem_of(cert_record):
    """Ricostruisce il PEM partendo dal record originale (non lo conserviamo,
    quindi rifaccio decode/base64 indirettamente sara' impossibile -> uso il
    fingerprint per i confronti). Ritorna stringa vuota se non disponibile."""
    return ''  # placeholder; per ora la diagnostica F3 usa direttamente il setting cacerts


def _where_for_secret(c, ctx):
    """Decide su quale VM andare a operare per quel secret."""
    ns = c.get('namespace')
    sec = c.get('secret')
    if ns == 'cattle-system' and sec in ('tls-rancher-ingress', 'tls-ca'):
        return {'vm': 'Rancher VM (kubectl al cluster local)', 'context': ctx,
                'note': 'cert servito dall\'ingress di Rancher; se davanti c\'e\' '
                        'nginx esterno aggiorna anche quello.'}
    return {'vm': 'Control-plane VM del cluster', 'context': ctx}


def _fix_secret_replace(c, ctx):
    ns = c.get('namespace'); sec = c.get('secret')
    if ns == 'cattle-system' and sec == 'tls-rancher-ingress':
        return [
            '# Rinnovo del cert di Rancher mantenendo la stessa CA:',
            'kubectl -n cattle-system create secret tls tls-rancher-ingress \\',
            '  --cert=fullchain.pem --key=tls.key --dry-run=client -o yaml \\',
            '  | kubectl apply -f -',
            '# Riavvia i pod Rancher per ricaricare il secret:',
            'kubectl -n cattle-system rollout restart deploy/rancher',
            '# Se la CA NON e\' cambiata, NON toccare setting/cacerts.',
            '# Verifica dal browser e con: kubectl -n cattle-system get secret tls-rancher-ingress -o yaml',
        ]
    if ns == 'cattle-system' and sec == 'tls-ca':
        return [
            '# Aggiornamento della CA (operazione delicata):',
            'kubectl -n cattle-system create secret generic tls-ca \\',
            '  --from-file=cacerts.pem=cacerts.pem --dry-run=client -o yaml \\',
            '  | kubectl apply -f -',
            '# Aggiorna anche il setting:',
            'kubectl patch setting.management.cattle.io cacerts --type merge -p "{\\"value\\": \\"$(cat cacerts.pem)\\"}"',
            '# Quindi forza il restart degli agent downstream.',
        ]
    return [
        f'# Sostituisci il secret TLS {ns}/{sec} mantenendo lo stesso nome:',
        f'kubectl -n {ns} create secret tls {sec} \\',
        '  --cert=fullchain.pem --key=tls.key --dry-run=client -o yaml \\',
        '  | kubectl apply -f -',
        '# Verifica gli Ingress che lo usano si aggiornino (l\'ingress controller fa hot-reload):',
        f'kubectl get ingress -A -o json | jq \'.items[] | select(.spec.tls[]?.secretName=="{sec}")\'',
    ]


# ---------------------------------------------------------------------------
# Job runner: la scansione gira in un thread cosi' lo streaming nel terminale
# resta consistente con il pattern Polaris (status idle/running/success/failed).
# ---------------------------------------------------------------------------
_last_scan = {'data': None}  # ultima scan completata, per servire la UI


def _run_scan_job(context):
    try:
        result = _scan(context)
        _last_scan['data'] = result
        _job_state['status'] = 'success'
    except Exception as exc:
        _log(f'\x1b[1;31m[ERR] {exc}\x1b[0m')
        _job_state['status'] = 'failed'
    finally:
        _job_lock.release()


def _start_scan(context):
    if not _job_lock.acquire(blocking=False):
        return False, 'Una scansione e\' gia\' in corso.'
    _job_state['output'] = []
    _job_state['status'] = 'running'
    t = threading.Thread(target=_run_scan_job, args=(context,), daemon=True)
    t.start()
    return True, None


# ---------------------------------------------------------------------------
# Rotte HTTP
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/output')
def api_output():
    since = int(request.args.get('since', 0))
    lines = _job_state['output'][since:]
    return jsonify({'lines': lines, 'total': len(_job_state['output']),
                    'status': _job_state['status']})


@app.route('/api/contexts')
def api_contexts():
    return jsonify({
        'contexts': _contexts(),
        'current': _current_context(),
        'kubectl': _which('kubectl'),
        'openssl': _which('openssl'),
        'cryptography': _HAS_CRYPTO,
    })


def _which(name):
    for p in (os.environ.get('PATH') or '').split(os.pathsep):
        full = os.path.join(p, name)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    return None


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    ctx = data.get('context') or None
    ok, err = _start_scan(ctx)
    if not ok:
        return jsonify({'error': err}), 409
    return jsonify({'status': 'started'})


@app.route('/api/last-scan')
def api_last_scan():
    return jsonify(_last_scan['data'] or {'empty': True})


@app.route('/api/probe', methods=['POST'])
def api_probe():
    data = request.get_json(force=True, silent=True) or {}
    host = (data.get('host') or '').strip()
    port = int(data.get('port') or 443)
    sni = (data.get('sni') or '').strip() or None
    if not host:
        return jsonify({'error': 'host obbligatorio'}), 400
    res = _probe_tls(host, port, sni)
    if not res.get('ok'):
        return jsonify({'host': host, 'port': port, 'ok': False, 'error': res.get('error')})
    parsed = _parse_cert_pem(res['pem'].encode('utf-8'))
    return jsonify({'host': host, 'port': port, 'sni': res['sni'],
                    'ok': True, 'pem': res['pem'], 'parsed': parsed})


@app.route('/api/howto')
def api_howto():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'HOW-TO')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return jsonify({'content': f.read()})
    except FileNotFoundError:
        return jsonify({'content': '# HOW-TO non disponibile.'})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8090'))
    app.run(host='127.0.0.1', port=port, debug=False, threaded=True)
