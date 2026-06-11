from __future__ import annotations

import collections
import contextlib
from dataclasses import dataclass
import json
import queue
import secrets
import threading
import time
import typing
import urllib.parse
import webbrowser
from concurrent.futures import Future, InvalidStateError

import flask
import github.Auth
import jwt
import pytest
import requests
import werkzeug.serving
from werkzeug.debug import DebuggedApplication
from werkzeug.exceptions import BadRequest
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.sansio.response import Response

import github

if typing.TYPE_CHECKING:
    from collections.abc import Generator, Iterator

    from github.AuthenticatedUser import AuthenticatedUser
    from github.NamedUser import NamedUser
    from github.Organization import Organization

    Event = tuple[str, str, dict[typing.Any, typing.Any]]

    Actor = NamedUser | AuthenticatedUser | Organization


@dataclass
class Github:
    pass


@dataclass
class Dc:
    session: requests.Session
    "Session with the main user token configured"


Forge = Github | Dc


@pytest.fixture(scope='session', autouse=True)
def app(
    request: pytest.FixtureRequest,
    session: requests.Session,
    org: Organization,
    is_github: bool,
    pytestconfig: pytest.Config,
) -> Iterator[App]:
    """App setup is a pretty complex process, and while DC tries to more or less
    follow the same workflow as github because the latter is interactive they
    can't be identical:

    - the official flow has to start with POST by an actual user
    - various explicit setup steps then have to be followed somewhat manually
    - technically it might be possible to use and drive the user's browser
      buuut that'a quite iffy, and it means having to write an entire automation
      script no top of
    """
    q = queue.Queue()

    base_url = pytestconfig.getoption('--base-url')
    assert isinstance(base_url, str)
    github_url = urllib.parse.urlsplit(base_url)
    flask_app.config['github_url'] = github_url
    flask_app.config['org'] = org
    flask_app.config['messages'] = q.put_nowait
    with contextlib.ExitStack() as onexit:
        app = dapp = DebuggedApplication(flask_app, evalex=True)
        if is_github:
            app = ProxyFix(app, x_for=1, x_proto=1, x_host=1)
        httpd = onexit.enter_context(
            werkzeug.serving.make_server('', 0, app, threaded=True)
        )
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        onexit.callback(httpd.shutdown)

        if is_github:
            tunnel_url, delete = request.getfixturevalue('make_tunnel')(
                *httpd.server_address
            )
            onexit.callback(delete)
            # maybe just allow `.ngrok-free.app`?
            url = urllib.parse.urlsplit(tunnel_url)
            dapp.trusted_hosts.append(url.netloc)
            flask_app.config['SERVER_NAME'] = url.netloc
            flask_app.config['PREFERRED_URL_SCHEME'] = 'https'
            forge = Github()
        else:
            netloc = "{}:{}".format(*httpd.server_address)
            url = urllib.parse.SplitResult("http", netloc, "", "", "")
            flask_app.config['SERVER_NAME'] = netloc
            flask_app.config['PREFERRED_URL_SCHEME'] = 'http'
            forge = Dc(session)

        with App(forge, github_url, q) as app:
            yield app


class AppInfo(typing.TypedDict):
    slug: str
    owner: dict
    name: str
    description: str
    permissions: str
    events: list[str]
    client_id: str
    client_secret: str
    webhook_secret: str
    pem: str


class User(typing.TypedDict):
    id: int
    node_id: str
    login: str
    type: typing.Literal['User', 'Organization', 'Bot']
    name: str | None
    email: str | None


class MiniRepository(typing.TypedDict):
    id: int
    node_id: str
    full_name: str
    name: str
    private: bool


class Installation(typing.TypedDict):
    id: int
    account: User
    app_id: int
    app_slug: str
    target_id: int
    target_type: typing.Literal['User', 'Organization']

    repository: dict | None
    repositories: list[MiniRepository]
    permissions: dict[str, typing.Literal['read', 'write']]
    events: list[str]

    created_at: str
    updated_at: str
    suspended_at: str | None
    suspended_by: str | None


class InstallationPayload(typing.TypedDict):
    installation: Installation
    requester: User | None
    sender: User


class Auth(typing.TypedDict):
    """The result of exchanging an auth code for auth tokens"""

    access_token: str
    expires_in: int | None
    refresh_token: str
    refresh_token_expires_in: int | None


class TokenInfo(typing.TypedDict):
    """Token metadata (/applications/{client_id}/token)"""

    id: int
    token: str
    token_last_eight: str
    hashed_token: str

    user: User
    app: dict

    created_at: str
    updated_at: str
    expires_at: str


class Authorization(Auth, TokenInfo):
    pass


class AuthorizationPayload(typing.TypedDict):
    sender: User


def to_site(u: urllib.parse.SplitResult) -> urllib.parse.SplitResult:
    """Takes a github API URL and converts it to a github site URL"""
    return u._replace(netloc='github.com') if u.netloc == 'api.github.com' else u


class App:
    """Manages the lifecycle of a test application...?"""

    def __init__(
        self,
        forge: Forge,
        github_url: urllib.parse.SplitResult,
        queue: queue.Queue[Event],
    ) -> None:
        self.forge = forge
        self.github_url = github_url
        self.info: Future[AppInfo] = Future()
        self.hooked = threading.Event()
        self.installations: dict[int, Future[Installation]] = collections.defaultdict(
            Future
        )
        self.authorizations: list[Authorization] = []
        self.authorizations_pending: dict[int, Future[Authorization]] = (
            collections.defaultdict(Future)
        )
        threading.Thread(target=self.process, args=(queue,), daemon=True).start()
        match forge:
            case Github():
                with flask_app.app_context():
                    index_url = flask.current_app.url_for('index', _external=True)
                # open local webapp to request that user creates the application
                webbrowser.open(index_url)
                self.info.result(60 * 5)  # give the user 5mn...?
            case Dc(session):
                # technically this should be able to do the same thing as the
                # github branch, by having the form autosubmit on load, but it
                # would require browser auth to be implemented (remove auth on
                # endpoints) and it would be a bit annoying to open browser tabs
                # into the voidwhen that's not necessary so hit DC directly
                with flask_app.app_context():
                    install_url, app_manifest = get_install_info()
                session.post(
                    install_url.geturl(),
                    data={'manifest': json.dumps(app_manifest)},
                    allow_redirects=True,
                ).raise_for_status()

    def __enter__(self) -> typing.Self:
        return self

    # have a test post-process which removes all auths and installs?
    def __exit__(self, *args) -> None:
        return None

    def process(self, queue: queue.Queue[Event]) -> None:
        while True:
            e = queue.get()
            print(*e[:-1], flush=True)
            match e:
                case ('hook', 'ping', _):
                    pass
                case ('app', 'created', appinfo):
                    self.info.set_result(typing.cast(AppInfo, appinfo))

                case ('authorization', 'granted', auth):
                    appinfo = self.info.result(0)
                    r = requests.post(
                        self.github_url._replace(
                            path=f'/applications/{appinfo["client_id"]}/token'
                        ).geturl(),
                        auth=(appinfo['client_id'], appinfo['client_secret']),
                        json={'access_token': auth['access_token']},
                    )
                    try:
                        r.raise_for_status()
                    except Exception as e:
                        with contextlib.suppress(InvalidStateError):
                            self.authorizations_pending[
                                auth['user']['id']
                            ].set_exception(e)
                        continue

                    self.authorizations.append(
                        auth := typing.cast(
                            Authorization,
                            {
                                **auth,
                                **r.json(),
                            },
                        )
                    )
                    with contextlib.suppress(InvalidStateError):
                        self.authorizations_pending[auth['user']['id']].set_result(auth)
                case ('hook', 'github_app_authorization.revoked', payload):
                    for i, a in enumerate(self.authorizations):
                        if payload['sender']['id'] == a['user']['id']:
                            break
                    else:  # no matching authorization recorded
                        continue
                    del self.authorizations[i]
                    self.authorizations_pending.pop(payload['sender']['id'])

                case ('hook', 'installation.created', payload):
                    inst = payload['installation']
                    if not (ip := self.installations[inst['account']['id']]).done():
                        ip.set_result(inst)
                case ('hook', 'installation.new_permissions_accepted', _):
                    pass
                case ('hook', 'installation.suspend', _):
                    pass
                case ('hook', 'installation.unsuspend', _):
                    pass
                case ('hook', 'installation.deleted', payload):
                    self.installations.pop(payload['sender']['id'], None)

                case e:
                    print("unknown event", *e, flush=True)

    @contextlib.contextmanager
    def as_app(self) -> Generator[requests.Session]:
        token = jwt.encode(
            {
                "iat": int(time.time()) - 60,
                "exp": int(time.time()) + 600,
                "iss": self.info.result(0)['client_id'],
            },
            self.info.result(0)['pem'].encode(),
            algorithm="RS256",
        )
        with requests.Session() as s:
            s.headers.update(
                Accept="application/vnd.github+json",
                Authorization=f"Bearer {token}",
            )
            yield s

    def install(self, account: Actor) -> Installation:
        # When trying to install into an account where it's already installed,
        # github just opens a configuration screen, so probably useless to allow
        # multiple installs, especially as the application creates IATs via JWT
        # requests (and can provide restrictions there), and IATs have a short
        # expiry (1h) so can easily create a bunch
        ip = self.installations[account.id]
        try:
            ip.set_running_or_notify_cancel()
        except Exception:
            pass
        else:
            appslug = self.info.result(0)["slug"]
            endpoint = (
                to_site(self.github_url)
                ._replace(
                    path=f'/apps/{appslug}/installations/new/permissions',
                    query=f'target_id={account.id}',
                )
                .geturl()
            )
            match self.forge:
                case Github():
                    # https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/migrating-oauth-apps-to-github-apps#prompt-users-to-install-your-github-app
                    webbrowser.open(endpoint)
                case Dc(session):
                    # don't check final status: without a `setup_url`, DC
                    # redirects to an internal URL which is not implemented
                    # (because it's not actually useful in headless)
                    session.get(endpoint, allow_redirects=True)

        return ip.result(60)

    def uninstall(self, account: Actor) -> None:
        ip = self.installations[account.id]
        if not (ip.done() or ip.running()):
            raise Exception(f"No installation for {account}")
        with self.as_app() as app:
            app.delete(
                self.github_url._replace(
                    path=f'/app/installations/{ip.result()["id"]}'
                ).geturl()
            )

    def iat(
        self,
        owner: Actor,
        permissions: dict[str, str] | None = None,
    ) -> github.Auth.AppInstallationAuth:
        installation = self.installations[owner.id].result()
        appinfo = self.info.result(0)
        return github.Auth.AppAuth(
            appinfo['client_id'], appinfo['pem']
        ).get_installation_auth(installation['id'], permissions)

    def authorize(self, account: AuthenticatedUser | NamedUser) -> Authorization:
        # Can have multiple authorization for the same (app, user) pair, seems
        # to be a remnant of oauth app as it's not really possible to restrict
        # the UAT?
        #
        # Can create permission-scoped tokens, but this is useless for
        # cross-owner actions.
        ap = self.authorizations_pending[account.id]
        try:
            ap.set_running_or_notify_cancel()
        except Exception:
            pass
        else:
            # https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#1-request-a-users-github-identity
            endpoint = (
                to_site(self.github_url)
                ._replace(
                    path="/login/oauth/authorize",
                    query=urllib.parse.urlencode(
                        {
                            'client_id': self.info.result(0)['client_id'],
                            # recommends switching to that user, but the current account is
                            # always preselected / at the top
                            'login': account.login,
                            # shows account picker (~like installation), incompatible with
                            # `login`
                            # 'prompt': 'select_account',
                            # content echoed back to oauth callback
                            # 'state': ...
                            # allows selecting one of the callback urls if multiple for some reason
                            # 'redirect_uri': ...
                            # fields for PKCE challenges
                        }
                    ),
                )
                .geturl()
            )
            match self.forge:
                case Github():
                    webbrowser.open(endpoint)
                case Dc(session):
                    session.get(endpoint, allow_redirects=True)
            # returns via redirection thingies
        return ap.result(60)

    def uat(self, user: AuthenticatedUser | NamedUser) -> github.Auth.AppUserAuth:
        auth = next(
            auth for auth in self.authorizations if auth['user']['id'] == user.id
        )
        appinfo = self.info.result(0)
        return github.Auth.AppUserAuth(
            appinfo['client_id'],
            appinfo['client_secret'],
            token=auth['access_token'],
            refresh_token=auth['refresh_token'],
        )


flask_app = flask.Flask('ghapp')
flask_app.debug = True


def get_install_info() -> tuple[urllib.parse.SplitResult, dict[str, typing.Any]]:
    manifest = {
        "name": "dctestapp" + secrets.token_hex(8),
        "url": flask.url_for('index', _external=True),
        # success redirection (for app creation)
        "redirect_url": flask.url_for("created", _external=True),
        # if set, redirect to callback_urls (specified or first) for auth on
        # install, otherwise redirect to setup_url
        "request_oauth_on_install": False,
        "callback_urls": [flask.url_for("oauth_callback", _external=True)],
        "setup_url": "",
        # redo setup after updating the installation (?)
        "setup_on_update": False,
        "description": "A Great App",
        "public": True,
        # webhook config
        "hook_attributes": {
            "url": flask.url_for("webhook", _external=True),
        },
        # webhook events (???)
        "default_events": [],
        "default_permissions": {
            # necessary to create private test repos as the tokens don't have it
            'administration': 'write',
            # actual perms the mergebot needs
            'contents': 'write',
            'deployments': 'write',
            'issues': 'write',
            'pull_requests': 'write',
            'statuses': 'read',
        },
    }
    secret = flask.current_app.config['secret'] = secrets.token_hex()
    path = '/settings/apps/new'
    if org := flask.current_app.config.get('org'):
        path = f"/organizations/{org.login}{path}"
    base_url = flask.current_app.config['github_url']
    return to_site(base_url)._replace(
        path=path, query=urllib.parse.urlencode({'state': secret})
    ), manifest


@flask_app.get("/")
def index() -> str:
    action, manifest = get_install_info()
    return flask.render_template_string(
        """
<h1>WARNING</h1>
<p>
    Not going to lie, validating the apps test is a bit of a bear as it requires
    a *lot* of github interactions which can't be automated, so the test suite
    is going to open links into your browser multiple times:
</p>
<ul>
    <li>create an application</li>
    <li>install the application into multiple accounts</li>
    <li>authorize the application into multiple accounts</li>
</ul>
<p>
    The suite may also try to fork a repository, you should fork into the account
    of the "primary" test token, which should be one of the accounts where the
    application was installed.
</p>
<p>
    Finally while the test suite will clean things up to the extent that it can,
    it doesn't really have a way to delete applications, so you'll have to do
    that after the test suite has completed.
</p>
<!-- /organizations/ORGANIZATION/settings/apps/new for org, not sure what oauth does then -->
<form method="POST" action="{{action}}">
    <input type="hidden" name="manifest" value="{{manifest}}">
    <input type="submit" value="Create App">
</form>
            """,
        action=action.geturl(),
        manifest=json.dumps(manifest),
    )


@flask_app.get("/created")
def created() -> Response:
    match (flask.current_app.config.get('secret'), flask.request.args.get('state')):
        case None, None:
            pass
        case secret, state if secret == state:
            pass
        case secret, state:
            raise BadRequest(
                f"App creation state mismatch: expected {secret}, got {state}"
            )
    code = flask.request.args['code']
    r = requests.post(
        flask.current_app.config['github_url']
        ._replace(path=f"/app-manifests/{code}/conversions")
        .geturl()
    )
    r.raise_for_status()
    appinfo = flask.current_app.config['appinfo'] = r.json()
    flask.current_app.config['messages'](('app', 'created', appinfo))
    return flask.redirect(flask.url_for('index'))


@flask_app.get('/oauth_callback')
def oauth_callback() -> Response:
    # If `request_oauth_on_install`, this callback URL can receive both
    # installation info ({installation_id, setup_action}) and oauth info ({code}).
    # The former should be ignored regardless, as it should be managed via
    # webhooks (which are trustworthy).
    code = flask.request.args.get('code')
    if not code:
        raise BadRequest("no oauth code")

    appinfo = flask.current_app.config['appinfo']
    base_url = flask.current_app.config['github_url']
    r = requests.post(
        to_site(base_url)._replace(path='/login/oauth/access_token').geturl(),
        params={
            'client_id': appinfo['client_id'],
            'client_secret': appinfo['client_secret'],
            'code': code,
            # 'redirect_url': ...
        },
    )
    r.raise_for_status()
    oauth = dict(urllib.parse.parse_qsl(r.text))

    flask.current_app.config['messages'](('authorization', 'granted', oauth))
    return flask.redirect(flask.url_for('index'))


@flask_app.post('/webhook')
def webhook() -> tuple[str, int]:
    # TODO: check signature
    event = flask.request.headers['X-Github-Event']
    payload = flask.request.get_json(force=True)
    if action := payload.get('action'):
        event += f'.{action}'
    flask.current_app.config['messages'](('hook', event, payload))
    return '', 201
