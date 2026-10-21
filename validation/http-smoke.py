#!/usr/bin/env python3
"""Real HTTP smoke for a CI-built Linux API; no downloads, external hosts or Web UI."""
import argparse
import ctypes
import http.client
import json
import os
from pathlib import Path
import platform
import re
import resource
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
from urllib.parse import quote, urlencode
import uuid


class SmokeFailure(Exception):
    pass


def require(condition, code):
    if not condition:
        raise SmokeFailure(code)


def interrupted(_signal, _frame):
    raise SmokeFailure('round_time_limit_or_interruption')


def listener(pid, binary, state, port):
    require(Path('/proc', str(pid), 'exe').resolve() == binary, 'unexpected_executable')
    require(Path('/proc', str(pid), 'cwd').resolve() == state, 'unexpected_working_directory')
    inodes = set()
    for fd in Path('/proc', str(pid), 'fd').iterdir():
        try:
            value = os.readlink(fd)
            if value.startswith('socket:['):
                inodes.add(value[8:-1])
        except FileNotFoundError:
            pass
    found = []
    for family in ('tcp', 'tcp6'):
        for line in Path('/proc/net', family).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A' and fields[9] in inodes:
                found.append((family, fields[1]))
    if not found:
        raise ConnectionError('listener_not_ready')
    require(found == [('tcp', f'0100007F:{port:04X}')], 'unexpected_tcp_listener')


def exercise(binary, resources, state, checks):
    proc = None
    db = None
    started = time.monotonic()
    # Work ends by 45s; finally allows at most another 10s for process shutdown.
    signal.signal(signal.SIGALRM, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    signal.setitimer(signal.ITIMER_REAL, 45)
    try:
        for name in ('templates', 'i18n'):
            require((resources/name).is_dir(), 'required_resource_directory_missing')
            shutil.copytree(resources/name, state/'resources'/name)
        for name in ('conf', 'runtime/cache', 'data', 'resources/public/upload'):
            (state/name).mkdir(parents=True, exist_ok=True, mode=0o700)
        with socket.socket() as available:
            available.bind(('127.0.0.1', 0))
            port = available.getsockname()[1]
        config = {
            'lang': 'en',
            'app': {'web-client': 0, 'register': False, 'register-status': 2,
                    'show-swagger': 0, 'token-expire': '1h', 'web-sso': False,
                    'disable-pwd-login': False, 'captcha-threshold': 3, 'ban-threshold': 10},
            'admin': {'title': 'CI smoke', 'hello-file': '', 'hello': ''},
            'gin': {'api-addr': f'127.0.0.1:{port}', 'mode': 'release',
                    'resources-path': 'resources', 'trust-proxy': '127.0.0.1'},
            'gorm': {'type': 'sqlite', 'max-idle-conns': 1, 'max-open-conns': 1},
            'cache': {'type': 'file', 'file-dir': './runtime/cache'},
            'rustdesk': {'id-server': '127.0.0.1:21116', 'relay-server': '127.0.0.1:21117',
                         'api-server': f'http://127.0.0.1:{port}', 'key': '', 'key-file': '',
                         'personal': 1, 'webclient-magic-queryonline': 0, 'ws-host': ''},
            'logger': {'path': './runtime/api.log', 'level': 'info', 'report-caller': False},
            'proxy': {'enable': False, 'host': ''}, 'ldap': {'enable': False},
            'jwt': {'key': '', 'expire-duration': '1h'},
        }
        # JSON is valid YAML; no third-party Python YAML package is needed.
        (state/'conf/config.yaml').write_text(json.dumps(config))
        original_parent = os.getpid()

        def child_setup():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(1, signal.SIGKILL, 0, 0, 0):
                os._exit(126)
            if os.getppid() != original_parent:
                os._exit(126)

        with open(state/'runtime/console.log', 'xb') as log:
            proc = subprocess.Popen([str(binary), '--config', './conf/config.yaml'],
                cwd=state, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                preexec_fn=child_setup,
                env={'PATH': '/usr/bin:/bin', 'HOME': str(state), 'TMPDIR': str(state/'runtime'),
                     'LANG': 'C.UTF-8', 'TZ': 'UTC'})

        def http(method, route, body=None, token=None, admin=False, status=200, raw=False):
            headers = {'Content-Type': 'application/json', 'Accept-Language': 'en'}
            if token:
                headers['api-token' if admin else 'Authorization'] = token if admin else 'Bearer '+token
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            try:
                connection.request(method, route, None if body is None else json.dumps(body), headers)
                response = connection.getresponse()
                payload = response.read(2 * 1024 * 1024)
                require(response.status == status, 'http_status_mismatch')
                if raw:
                    return payload
                value = json.loads(payload) if payload else None
                if status == 200:
                    require(not isinstance(value, dict) or 'error' not in value, 'api_error_response')
                return value
            finally:
                connection.close()

        def admin_api(route, body=None, token=None):
            response = http('GET' if body is None else 'POST', '/api/admin'+route,
                            body, token, admin=True)
            require(response.get('code') == 0, 'admin_api_error')
            return response.get('data')

        deadline = time.monotonic()+20
        while True:
            require(proc.poll() is None, 'api_exited_before_readiness')
            try:
                listener(proc.pid, binary, state, port)
                options = admin_api('/login-options')
                break
            except (OSError, ValueError):
                require(time.monotonic() < deadline, 'api_readiness_timeout')
                time.sleep(0.1)
        require(options.get('register') is False, 'registration_not_disabled')
        checks.append('fresh_process_has_only_owned_ipv4_loopback_listener')
        match = re.search(r'Admin Password Is:\s*([A-Za-z0-9]{8})\b',
                          (state/'runtime/console.log').read_text(errors='replace'))
        require(match is not None, 'fresh_initial_admin_password_not_found')
        admin_token = admin_api('/login', {'username': 'admin', 'password': match.group(1),
                                        'platform': 'ci-smoke'})['token']
        username, password = 'ci_'+secrets.token_hex(6), secrets.token_urlsafe(24)
        group = admin_api('/user/detail/1', token=admin_token)['group_id']
        form = {'username': username, 'group_id': group, 'is_admin': False,
                'status': 2, 'nickname': 'Synthetic CI user'}
        admin_api('/user/create', form, admin_token)
        users = admin_api('/user/list?'+urlencode({'username': username, 'page': 1, 'page_size': 10}),
                          token=admin_token)['list']
        found = [user for user in users if user['username'] == username]
        require(len(found) == 1 and found[0]['is_admin'] is False, 'synthetic_user_mismatch')
        user_id = found[0]['id']
        admin_api('/user/changePwd', {'id': user_id, 'password': password}, admin_token)
        admin_api('/user/update', {**form, 'id': user_id, 'status': 1}, admin_token)

        device_id, device_uuid = '9'+str(secrets.randbelow(100000000)).zfill(8), str(uuid.uuid4())

        def login(device, identity):
            response = http('POST', '/api/login', {'username': username, 'password': password,
                'id': device, 'uuid': identity, 'type': 'account', 'autoLogin': True,
                'deviceInfo': {'name': 'ci-synthetic', 'os': 'Mac OS', 'type': 'client'}})
            require(response.get('type') == 'access_token' and
                    re.fullmatch(r'[a-f0-9]{64}', response.get('access_token', '')),
                    'native_token_not_64_hex')
            return response['access_token']

        def current(token):
            user = http('POST', '/api/currentUser', {}, token)
            require(user.get('name') == username and user.get('is_admin') is False,
                    'native_user_identity_mismatch')

        first = login(device_id, device_uuid)
        second = login('8'+device_id[1:], str(uuid.uuid4()))
        require(first != second, 'sessions_not_distinct')
        current(first)
        current(second)
        http('POST', '/api/currentUser', {}, status=401)
        checks.append('native_64_hex_login_two_devices_and_missing_token_rejection')
        sysinfo = {'id': device_id, 'uuid': device_uuid, 'cpu': 'synthetic', 'memory': '0',
                   'os': 'Mac OS', 'username': username, 'hostname': 'ci-synthetic', 'version': '1.5.0'}
        require(http('POST', '/api/sysinfo', sysinfo, first, raw=True) == b'SYSINFO_UPDATED', 'sysinfo_failed')
        http('POST', '/api/heartbeat', {'id': device_id, 'uuid': device_uuid, 'ver': 1}, first)
        peers = http('GET', '/api/peers?current=1&pageSize=100&accessible=&status=1', token=first)
        require(any(peer.get('id') == device_id and peer.get('user_name') == username
                    for peer in peers.get('data', [])), 'own_reported_device_missing')
        checks.append('own_device_report_and_list')
        personal = http('POST', '/api/ab/personal', token=first)
        guid = personal.get('guid')
        require(isinstance(guid, str) and guid and personal.get('rule') == 3, 'personal_ab_missing')
        peer_route = '/api/ab/peers?'+urlencode({'current': 1, 'pageSize': 100, 'ab': guid})
        require(http('POST', peer_route, token=first).get('total') == 0, 'personal_ab_not_fresh')
        http('POST', '/api/ab/peer/add/'+quote(guid, safe=''), {'id': device_id, 'username': username,
             'hostname': 'ci-synthetic', 'platform': 'Mac OS', 'alias': 'CI only', 'tags': [],
             'hash': '', 'password': '', 'forceAlwaysRelay': 'false'}, first, raw=True)
        require(any(peer.get('id') == device_id for peer in http('POST', peer_route, token=first).get('data', [])),
                'personal_ab_read_after_write_failed')
        http('DELETE', '/api/ab/peer/'+quote(guid, safe=''), [device_id], first, raw=True)
        require(http('POST', peer_route, token=first).get('total') == 0, 'personal_ab_delete_failed')
        checks.append('personal_address_book_add_read_delete')

        # SQL is restricted to this fresh process's private DB and this synthetic user's tokens.
        listener(proc.pid, binary, state, port)
        dbfile = state/'data/rustdeskapi.db'
        require(not dbfile.is_symlink() and stat.S_ISREG(dbfile.stat().st_mode)
                and stat.S_IMODE(dbfile.stat().st_mode) == 0o600, 'unexpected_private_db')
        db = sqlite3.connect('file:'+quote(str(dbfile), safe='/')+'?mode=rw', uri=True, timeout=3)
        required = {'id', 'user_id', 'token', 'device_uuid', 'device_id', 'expired_at', 'created_at', 'updated_at'}
        require(required <= {row[1] for row in db.execute('PRAGMA table_info("user_tokens")')}, 'unexpected_token_schema')
        require(db.execute('SELECT username,is_admin FROM users WHERE id=?', (user_id,)).fetchone() == (username, 0),
                'unexpected_sql_user')
        original = db.execute('SELECT id FROM user_tokens WHERE user_id=? AND token=? AND device_uuid=?',
                              (user_id, first, device_uuid)).fetchall()
        require(len(original) == 1, 'unexpected_source_token_row')
        legacy = secrets.token_hex(16)
        with db:
            inserted = db.execute('INSERT INTO user_tokens (user_id,device_uuid,device_id,token,expired_at,created_at,updated_at) '
                'SELECT user_id,?,?,?, ?,created_at,updated_at FROM user_tokens WHERE id=? AND user_id=? AND token=?',
                (str(uuid.uuid4()), 'legacy-ci-device', legacy, int(time.time())+300,
                 original[0][0], user_id, first)).rowcount
        require(inserted == 1, 'legacy_fixture_insert_failed')
        for token in (first, legacy):
            with db:
                updated = db.execute('UPDATE user_tokens SET expired_at=? WHERE user_id=? AND token=?',
                                     (int(time.time())+300, user_id, token)).rowcount
            require(updated == 1, 'unexpected_renewal_row_count')
            lower = int(time.time())+3590
            current(token)
            renewed = db.execute('SELECT token,expired_at FROM user_tokens WHERE user_id=? AND token=?',
                                 (user_id, token)).fetchall()
            require(len(renewed) == 1 and renewed[0][0] == token
                    and lower <= renewed[0][1] <= int(time.time())+3610, 'same_token_renewal_failed')
        checks.append('new_64_hex_and_legacy_32_hex_same_token_renewal')
        http('POST', '/api/logout', {}, second)
        http('POST', '/api/currentUser', {}, second, status=401)
        current(first)
        for token in (first, legacy):
            http('POST', '/api/logout', {}, token)
            http('POST', '/api/currentUser', {}, token, status=401)
        checks.append('single_device_logout_isolated_and_revoked_tokens_rejected')
        listener(proc.pid, binary, state, port)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if db is not None:
            db.close()
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=2)
        require(proc is None or proc.poll() is not None, 'api_process_not_stopped')
    return round(time.monotonic()-started, 3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--resources', type=Path, required=True)
    args = parser.parse_args()
    require(platform.system() == 'Linux' and os.geteuid() != 0, 'requires_linux_non_root_ci_user')
    require(args.binary.is_absolute() and args.resources.is_absolute(), 'absolute_input_paths_required')
    binary, resources = args.binary.resolve(), args.resources.resolve()
    require(binary.is_file() and os.access(binary, os.X_OK) and resources.is_dir(), 'invalid_ci_inputs')
    os.umask(0o077)
    report = {'result': 'failed', 'real_http': True, 'real_client_executed': False, 'checks': []}
    try:
        with tempfile.TemporaryDirectory(prefix='rd-api-ci-') as folder:
            report['runtime_seconds'] = exercise(binary, resources, Path(folder).resolve(), report['checks'])
        report.update(result='passed', process_stopped=True, temporary_data_removed=True)
    except Exception as exc:
        report['error'] = str(exc) if isinstance(exc, SmokeFailure) else type(exc).__name__
        print(json.dumps(report), flush=True)
        return 1
    print(json.dumps(report), flush=True)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SmokeFailure as exc:
        print(json.dumps({'result': 'failed', 'error': str(exc)}))
        raise SystemExit(1)
