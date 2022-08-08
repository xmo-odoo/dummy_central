import base64
import configparser
import contextlib
import json
import queue
import os
import random
import subprocess
import threading
import time
import urllib.parse
from wsgiref.simple_server import make_server, WSGIRequestHandler

import github as pygithub
import pytest
import requests

#pygithub.enable_console_debug_logging()

def pytest_addoption(parser):
    parser.addoption('--url', '--base-url', default='https://api.github.com')

@pytest.fixture(scope='session')
def is_github(pytestconfig):
    return 'api.github.com' in pytestconfig.getoption('--base-url')

@pytest.fixture(scope='session')
def config(pytestconfig):
    """Reads github.token and github.owner from the pytest config file.

    github.token is the user used for interactions, github.owner is the name of
    an org available for creating repos in (user should have access rights to
    it).

    :returns: a map of {org: orgname, token: token}
    """
    conf = configparser.ConfigParser(interpolation=None)
    conf.read([pytestconfig.inifile])

    return {
        'org': conf.get('github', 'owner'),
        'token': conf.get('github', 'token'),
        'users': {
            name: conf.get(section, 'token', fallback=None)
            for name, section in [
                ('base', 'github'),
                ('a', 'role_reviewer'),
                ('b', 'role_self_reviewer'),
                ('c', 'role_other'),
                (None, None),
            ]
        }
    }

@pytest.fixture(scope="session")
def users(pytestconfig, config):
    return lambda key: pygithub.Github(config['users'][key], base_url=pytestconfig.getoption('--base-url'))

@pytest.fixture(scope="session")
def github(users):
    """
    :rtype: github.Github
    """
    return users('base')

@pytest.fixture(scope="session")
def user(github):
    return github.get_user()

@pytest.fixture(scope="session")
def org(github, config):
    return github.get_organization(config['org'])

@pytest.fixture(autouse=True)
def slow_down_tests(is_github):
    """ Avoids spamming github too much, and also helpful when ending tests
    right after creation repositories, as github can complain that the repo does
    not yet exist on-disk and thus can't be deleted.
    """
    yield
    if is_github:
        time.sleep(5)

class WebhookReceiverApp:
    def __init__(self, queue):
        self.queue = queue
    def __call__(self, environ, start_response):
        event_type = environ.get('HTTP_X_GITHUB_EVENT')
        if event_type is None:
            response = b"Expected github webhook event."
            start_response('400 Bad Request', [
                ('Content-Type', 'text/plain'),
                ('Content-Length', str(len(response))),
            ])
            return [response]

        length = int(environ.get('CONTENT_LENGTH', 0))
        event_payload = json.loads(environ['wsgi.input'].read(length))
        self.queue.put_nowait((event_type, event_payload))

        start_response('200 OK', [
            ('Content-Type', 'text/plain'),
            ('Content-Length', '0')
        ])
        return [b""]

@pytest.fixture(scope="session")
def _ngrok(request):
    web_addr = 'http://localhost:4040/api'
    try:
        time.sleep(random.SystemRandom().randint(1, 10))
        requests.get(web_addr)
    except requests.exceptions.ConnectionError:
        p = subprocess.Popen([
            'ngrok', 'start', '--none', '--region', 'eu',
        ], stdout=subprocess.DEVNULL)
        request.addfinalizer(p.terminate)
        for _ in range(5):
            time.sleep(1)
            with contextlib.suppress(requests.exceptions.ConnectionError):
                requests.get(web_addr)
                break
        else:
            raise Exception("Unable to connect to ngrok")

    yield web_addr

@pytest.fixture(scope="session")
def make_tunnel(_ngrok):
    web_addr = _ngrok

    tunnels = []
    s = requests.Session()
    def add(address, port):
        addr = f'{address}:{port}'

        s.post(f'{web_addr}/tunnels', json={
            'name': str(port),
            'proto': 'http',
            'bind_tls': True, # only https
            'addr': addr,
            'inspect': True,
        }).raise_for_status()

        tunnel = f'{web_addr}/tunnels/{port}'
        for _ in range(10):
            r = s.get(tunnel)
            # not created yet, wait and retry
            if r.status_code == 404:
                time.sleep(1)
                continue

            # check for weird responses
            r.raise_for_status()
            tunnels.append(tunnel)
            return r.json()['public_url'], lambda: delete(tunnel)

    def delete(url):
        requests.delete(url)
        for _ in range(10):
            time.sleep(1)
            r = requests.get(url)
            # check if deletion is done
            if r.status_code == 404:
                break
            r.raise_for_status()
        else:
            raise TimeoutError("ngrok tunnel deletion failed")
        tunnels.remove(url)

    yield add

    while tunnels:
        delete(tunnels[-1])

class NoLoggingHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass

@pytest.fixture
def endpoint(request, make_tunnel):
    """Per-test webhooks endpoint.

    Avoids tests interfering with one another when the webhooks arrive later
    than expected
    """
    q = queue.Queue()

    with make_server('', 0, WebhookReceiverApp(q), handler_class=NoLoggingHandler) as httpd:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        request.addfinalizer(httpd.shutdown)

        url, delete = make_tunnel(*httpd.server_address)

        yield url, lambda timeout=60: q.get(timeout=timeout)

        delete()

@pytest.fixture(scope='session')
def repo(org, config):
    # fixme: random name?
    repo_id = base64.b32encode(os.urandom(5)).decode()
    r = org.create_repo(f'default-repo-{repo_id}')
    s = requests.Session()
    s.headers['Authorization'] = f'token {config["token"]}'
    for t in [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]:
        time.sleep(t)
        if s.head(r.url).ok:
            break
    else:
        raise Exception(f"Never saw repository {r.url!r}")

    # create garbage on the default branch
    r.create_file(path='dummy', message="dummy", content="dummy")
    yield r

    try:
        r.delete()
    except pygithub.GithubException as e:
        if e.status == 404:
            return
        raise
