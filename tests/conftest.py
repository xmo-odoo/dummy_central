import base64
import contextlib
import itertools
import json
import queue
import os
import random
import subprocess
import threading
import time
from wsgiref.simple_server import make_server, WSGIRequestHandler

import github as pygithub
import pytest
import requests

from . import make_branch, safe_delete, make_branchname

# pygithub.enable_console_debug_logging()


def pytest_addoption(parser):
    parser.addini('users', help="Path to a users json file.")
    parser.addoption('--users', help="Path to a users json file.")
    parser.addoption('--url', '--base-url', default='https://api.github.com')


@pytest.fixture(scope='session')
def is_github(pytestconfig):
    return 'api.github.com' in pytestconfig.getoption('--base-url')


role_user_mapping = {
    'user': 'base',
    'reviewer': 'a',
    'self_reviewer': 'b',
    'other': 'c',
}


@pytest.fixture(scope='session')
def config(pytestconfig):
    """Reads github.token and github.owner from the pytest config file.

    github.token is the user used for interactions, github.owner is the name of
    an org available for creating repos in (user should have access rights to
    it).

    :returns: a map of {org: orgname, token: token}
    """
    if p := pytestconfig.getoption('--users'):
        with pytestconfig.invocation_params.dir.joinpath(p).open('rb') as f:
            users = json.load(f)
    elif p := pytestconfig.getini('users'):
        with pytestconfig.inipath.parent.joinpath(p).open('rb') as f:
            users = json.load(f)
    else:
        raise ValueError("A users json file is required.")

    org = None
    tokens = {}
    for k, v in users.items():
        match v.get('role'):
            case 'owner':
                org = k
            case r if r:
                tokens[role_user_mapping[r]] = v['token'][0]
    return {
        'org': org,
        'token': tokens['base'],
        'users': tokens,
    }


@pytest.fixture(scope="session")
def users(pytestconfig, config):
    return lambda key: pygithub.Github(
        auth=pygithub.Auth.Token(config['users'][key]) if key else None,
        base_url=pytestconfig.getoption('--base-url'),
    )


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
    """Avoids spamming github too much, and also helpful when ending tests
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
            start_response(
                '400 Bad Request',
                [
                    ('Content-Type', 'text/plain'),
                    ('Content-Length', str(len(response))),
                ],
            )
            return [response]

        length = int(environ.get('CONTENT_LENGTH', 0))
        event_payload = json.loads(environ['wsgi.input'].read(length))
        self.queue.put_nowait((event_type, event_payload))

        start_response(
            '200 OK', [('Content-Type', 'text/plain'), ('Content-Length', '0')]
        )
        return [b""]


@pytest.fixture(scope="session")
def _ngrok(request):
    web_addr = 'http://localhost:4040/api'
    try:
        time.sleep(random.SystemRandom().randint(1, 10))
        requests.get(web_addr)
    except requests.exceptions.ConnectionError:
        p = subprocess.Popen(
            [
                'ngrok',
                'start',
                '--none',
                '--region',
                'eu',
            ],
            stdout=subprocess.DEVNULL,
        )
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

        s.post(
            f'{web_addr}/tunnels',
            json={
                'name': str(port),
                'proto': 'http',
                'schemes': ['https'],
                'addr': addr,
                'inspect': True,
            },
        ).raise_for_status()

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
        raise TimeoutError(f"Unable to create tunnel to {addr}")

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
def endpoint(request, is_github):
    """Per-test webhooks endpoint.

    Avoids tests interfering with one another when the webhooks arrive later
    than expected
    """
    q = queue.Queue()

    with make_server(
        '', 0, WebhookReceiverApp(q), handler_class=NoLoggingHandler
    ) as httpd:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        if is_github:
            url, delete = request.getfixturevalue('make_tunnel')(*httpd.server_address)
        else:
            url = "http://{}:{}".format(*httpd.server_address)

            def delete():
                pass

        yield url, lambda timeout=60: q.get(timeout=timeout)

        delete()
        httpd.shutdown()


def random_id(n):
    return base64.b32encode(os.urandom(n)).decode()


@pytest.fixture(scope='session')
def session(config):
    s = requests.Session()
    s.headers['Authorization'] = f'token {config["token"]}'
    return s


@pytest.fixture(scope='session')
def repo(org, session):
    r = org.create_repo(f'default-repo-{random_id(5)}', auto_init=True)
    for t in [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]:
        time.sleep(t)
        if session.head(r.url).ok:
            break
    else:
        raise Exception(f"Never saw repository {r.url!r}")

    yield r

    safe_delete(r)


@pytest.fixture
def create_repo(request, session, org):
    repos = []

    def _create():
        r = org.create_repo(f'r-{random_id(5)}', auto_init=True)
        for t in [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]:
            time.sleep(t)
            if session.head(r.url).ok:
                break
        else:
            raise Exception(f"Never saw repository {r.url!r}")
        repos.append(r)
        return r

    yield _create

    for r in repos:
        safe_delete(r)


@pytest.fixture(scope='module')  # have every thing work off of the same pr
def pr(repo, config):
    branchname = make_branchname()
    ref = make_branch(repo, branchname)
    yield repo.create_pull(repo.default_branch, branchname, title="test")
    ref.delete()


@pytest.fixture
def genbranch(request):
    counter = itertools.count()
    next(counter)  # completely unnecessary but looks a bit nicer maybe
    fname = request.function.__name__

    yield lambda: make_branchname(f"{fname}-{next(counter)}-")
