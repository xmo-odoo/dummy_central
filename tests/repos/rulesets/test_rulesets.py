import contextlib
import secrets
import subprocess
import time
import uuid
from urllib.parse import urlsplit

import requests
import pytest
from github import GithubException, UnknownObjectException

from ... import check


@pytest.fixture
def rulesets_url(repo):
    return f"{repo.url}/rulesets"


@pytest.fixture
def github_headers(config):
    return {
        "Authorization": f"token {config['token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


@pytest.fixture
def create_ruleset(session, request, rulesets_url, github_headers):
    def _create(payload, rulesets_url=rulesets_url):
        resp = session.post(rulesets_url, headers=github_headers, json=payload)
        ruleset = resp.json()
        if not resp.ok:
            raise GithubException(
                resp.status_code,
                ruleset,
                resp.headers,
                f"Failed to create ruleset {payload}",
            )
        request.addfinalizer(
            lambda: session.delete(
                ruleset["_links"]['self']['href'], headers=github_headers
            )
        )
        return ruleset

    yield _create


def list_rulesets(rulesets_url, github_headers, session):
    resp = session.get(rulesets_url, headers=github_headers)
    resp.raise_for_status()
    return resp.json()


@pytest.mark.parametrize(
    "pattern,success",
    [
        ("~MAGIC", False),
        ("invalid_pattern", False),
        ("heads/invalid-pattern", False),
        ("*/invalid-pattern", False),
        ("*invalid-pattern", False),
        ("refs/heads/some-branch", True),
        ("refs/heads/staging.*", True),
        ("refs/heads/*", True),
        ("refs/*", False),
        ("refs/*/foo", False),
    ],
)
def test_create_patterns(
    create_ruleset,
    pattern,
    success,
):
    handler = contextlib.nullcontext() if success else pytest.raises(GithubException)
    with handler as err:
        create_ruleset(
            {
                "name": "Invalid Pattern",
                "target": "branch",
                "enforcement": "active",
                "bypass_actors": [],
                "conditions": {
                    "ref_name": {
                        "include": [pattern],
                        "exclude": [],
                    }
                },
                "rules": [{"type": "creation"}],
            }
        )
    if success:
        return
    else:
        assert err.value.status == 422
        assert err.value.data == {
            "status": "422",
            "message": "Validation Failed",
            "errors": [f"Invalid target patterns: '{pattern}'"],
            "documentation_url": "https://docs.github.com/rest/repos/rules#create-a-repository-ruleset",
        }


def test_create_delete(create_ruleset, rulesets_url, github_headers, session):
    assert list_rulesets(rulesets_url, github_headers, session) == []
    ruleset = create_ruleset(
        {
            "name": "Test Ruleset",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["~ALL"],
                    "exclude": [],
                }
            },
            "rules": [{"type": "creation"}],
        }
    )
    assert [ruleset["id"]] == [
        r["id"] for r in list_rulesets(rulesets_url, github_headers, session)
    ]
    assert ruleset["name"] == "Test Ruleset"
    assert ruleset["target"] == "branch"
    assert ruleset["enforcement"] == "active"
    assert ruleset["rules"][0]["type"] == "creation"

    session.delete(
        ruleset["_links"]['self']['href'], headers=github_headers
    ).raise_for_status()
    assert list_rulesets(rulesets_url, github_headers, session) == []


def invite_user(request, repo, token, user):
    invitation = repo.add_to_collaborators(user.login, permission="push")

    @request.addfinalizer
    def _uninvite():
        with contextlib.suppress(UnknownObjectException):
            repo.remove_invitation(invitation.id)

    request.addfinalizer(lambda: repo.remove_from_collaborators(user.login))
    for inv in user.get_invitations():
        resp = requests.request(
            "PATCH" if inv.repository == repo else "DELETE",
            inv.url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"token {token}",
            },
        )
        resp.raise_for_status()

    for i in range(0, 6):
        with contextlib.suppress(UnknownObjectException):
            collab = repo.get_collaborator_permission(user.login)
            if collab in ("push", "write", "admin"):
                return
        time.sleep(2**i)
    else:
        raise RuntimeError(f"User {user.login} never got access to {repo.full_name!r}")


def test_check_permission(request, repo, users, config):
    base_login = users("base").get_user().login
    assert repo.get_collaborator_permission(base_login) == 'admin'
    # assert repo.get_collaborator_role_name(base_login) == "admin"
    a_login = users("a").get_user().login
    assert repo.get_collaborator_permission(a_login) == 'read'
    # assert repo.get_collaborator_role_name(a_login) == "read"

    b = users("b").get_user()
    invite_user(request, repo, config['users']['b'], b)

    assert repo.get_collaborator_permission(b.login) == 'write'
    # assert repo.get_collaborator_role_name(b_login) == "push"

    c = users("c").get_user()
    invite_user(request, repo, config['users']['c'], c)

    assert repo.get_collaborator_permission(c.login) == 'write'
    # assert repo.get_collaborator_role_name(c.login) == "write"

    assert {c.login for c in repo.get_collaborators()} == {base_login, b.login, c.login}


def test_restrict_create_contents(request, org, create_ruleset):
    # /contents can only create branches if the repository is empty
    repo = check(
        request, org.create_repo(f'restrict-create-contents-{secrets.token_hex(5)}')
    )

    create_ruleset(
        {
            "name": "Restrict creation",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["~ALL"],
                    "exclude": [],
                }
            },
            "rules": [{"type": "creation"}],
        },
        rulesets_url=f"{repo.url}/rulesets",
    )

    with pytest.raises(GithubException) as err:
        repo.create_file(
            "foo.txt",
            "initial commit",
            "blorp",
            "mybranch",
        )
    assert err.value.status == 409
    assert err.value.data == {
        "status": "409",
        "metadata": {},
        "message": "Repository rule violations found\n\nCannot create ref due to creations being restricted.\n\n",
        "documentation_url": "https://docs.github.com/rest/repos/contents#create-or-update-file-contents",
    }


def test_restrict_update_contents(repo, create_ruleset):
    create_ruleset(
        {
            "name": "Restrict update",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["~ALL"],
                    "exclude": [],
                }
            },
            "rules": [{"type": "update"}],
        }
    )

    with pytest.raises(GithubException) as err:
        repo.create_file(
            "foo.txt",
            "initial commit",
            "blorp",
            "main",
        )
    assert err.value.status == 409
    assert err.value.data == {
        "status": "409",
        "metadata": {},
        "message": "Repository rule violations found\n\nCannot update this protected ref.\n\n",
        "documentation_url": "https://docs.github.com/rest/repos/contents#create-or-update-file-contents",
    }


@pytest.mark.skip(
    reason="Rename not implemented in dummy central, and apparently rename is not a protected operation anyway..."
)
def test_rename_branch(repo, create_ruleset):
    head = repo.get_branch("main").commit.sha
    repo.create_git_ref(ref="refs/heads/xxx", sha=head)
    create_ruleset(
        {
            "name": "Restrict creation",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["~ALL"],
                    "exclude": [],
                }
            },
            "rules": [{"type": "creation"}, {"type": "update"}],
        }
    )
    repo.rename_branch("xxx", "yyy")


def test_merge_branch(repo, create_ruleset):
    head = repo.get_branch("main").commit.sha
    repo.create_git_ref(ref="refs/heads/feature-branch", sha=head)

    create_ruleset(
        {
            "name": "Restrict merge",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["~ALL"],
                    "exclude": [],
                }
            },
            "rules": [{"type": "update"}],
        }
    )

    repo.merge("main", "feature-branch")


def test_reference(repo, create_ruleset):
    main = repo.get_git_ref("heads/main")
    repo.create_git_ref(ref="refs/heads/fgspiohfa", sha=main.object.sha)

    create_ruleset(
        {
            "name": "Restrict reference",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["~ALL"],
                    "exclude": ["refs/heads/staging.*"],
                }
            },
            "rules": [{"type": "creation"}, {"type": "update"}],
        }
    )

    with pytest.raises(GithubException) as err:
        repo.create_git_ref(ref="refs/heads/kdshfalkfh", sha=main.object.sha)
    assert err.value.status == 422
    assert err.value.data == {
        "status": "422",
        "message": "Reference update failed",
        "documentation_url": "https://docs.github.com/rest/git/refs#create-a-reference",
    }

    main.edit(sha=main.object.sha)

    parent = repo.get_git_commit(main.object.sha)
    new_head = repo.create_git_commit("Update main", parent.tree, [parent])
    with pytest.raises(GithubException) as err:
        main.edit(sha=new_head.sha)
    assert err.value.status == 422
    assert err.value.data == {
        "status": "422",
        "message": "Repository rule violations found\n\nCannot update this protected ref.\n\n",
        "documentation_url": "https://docs.github.com/rest/git/refs#update-a-reference",
    }

    r = repo.create_git_ref(ref="refs/heads/staging.main", sha=main.object.sha)
    r.edit(sha=new_head.sha)

    with pytest.raises(GithubException) as err:
        repo.create_git_ref(ref="refs/heads/stagings.main", sha=main.object.sha)


@pytest.mark.parametrize("user", ["base", "a"])
def test_restrict_push_create(
    request, create_ruleset, repo, config, users, user, tmp_path_factory
):
    if user != "base":
        non_admin_user = users(user).get_user()
        invite_user(request, repo, config['users'][user], non_admin_user)

    clone_dir = tmp_path_factory.mktemp("restrict_updates")
    url = (
        (r := urlsplit(repo.clone_url))
        ._replace(netloc=f'{config["users"][user]}@{r.netloc}')
        .geturl()
    )
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.http.allow=always",
            "clone",
            url,
            str(clone_dir),
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            '-C',
            clone_dir,
            "-c",
            "protocol.http.allow=always",
            "push",
            "origin",
            "main:refs/heads/main2",
        ],
        check=True,
    )

    create_ruleset(
        {
            "name": "Restrict creation",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": ["~ALL"],
                    "exclude": [],
                }
            },
            "rules": [
                {
                    "type": "creation",
                }
            ],
        }
    )

    p = subprocess.run(
        [
            "git",
            '-C',
            clone_dir,
            "-c",
            "protocol.http.allow=always",
            "push",
            "origin",
            "main:refs/heads/main3",
        ],
        text=True,
        stderr=subprocess.PIPE,
    )
    assert p.returncode != 0
    assert p.stderr.startswith(
        "remote: error: GH013: Repository rule violations found for refs/heads/main3."
    )
    assert 'remote: - Cannot create ref due to creations being restricted.' in p.stderr


@pytest.mark.parametrize("user", ["base", "a"])
@pytest.mark.parametrize(
    "pattern", ["~ALL", '~DEFAULT_BRANCH', 'refs/heads/main', 'refs/heads/other']
)
def test_restrict_push_update(
    request, create_ruleset, repo, config, users, user, tmp_path_factory, pattern
):
    if user != "base":
        non_admin_user = users(user).get_user()
        invite_user(request, repo, config['users'][user], non_admin_user)

    clone_dir = tmp_path_factory.mktemp("restrict_updates")
    url = (
        (r := urlsplit(repo.clone_url))
        ._replace(netloc=f'{config["users"][user]}@{r.netloc}')
        .geturl()
    )
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.http.allow=always",
            "clone",
            url,
            str(clone_dir),
        ],
        check=True,
    )

    unique_file = clone_dir / f"foo_{uuid.uuid4().hex}.txt"
    unique_file.write_text("first commit\n")
    subprocess.run(["git", '-C', clone_dir, "add", unique_file], check=True)
    subprocess.run(
        [
            "git",
            '-C',
            clone_dir,
            '-c',
            'user.name=user',
            '-c',
            'user.email=user@example.com',
            "commit",
            "-m",
            "first commit",
        ],
        check=True,
    )
    subprocess.run(
        [
            "git",
            '-C',
            clone_dir,
            "-c",
            "protocol.http.allow=always",
            "push",
            "origin",
            "main",
        ],
        check=True,
    )

    create_ruleset(
        {
            "name": "Restrict updates",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {
                "ref_name": {
                    "include": [pattern],
                    "exclude": [],
                }
            },
            "rules": [
                {
                    "type": "update",
                    "parameters": {
                        "update_allows_fetch_and_merge": True,
                    },
                }
            ],
        }
    )

    unique_file.write_text("second commit\n")
    subprocess.run(
        [
            "git",
            '-C',
            clone_dir,
            '-c',
            'user.name=user',
            '-c',
            'user.email=user@example.com',
            "commit",
            "-am",
            "second commit",
        ],
        check=True,
    )
    p = subprocess.run(
        [
            "git",
            '-C',
            clone_dir,
            "-c",
            "protocol.http.allow=always",
            "push",
            "origin",
            "main",
        ],
        text=True,
        stderr=subprocess.PIPE,
    )
    if pattern == 'refs/heads/other':
        assert p.returncode == 0, (
            "if the rule is on an unrelated branch the push should work fine"
        )
    else:
        assert p.returncode != 0
        assert p.stderr.startswith(
            "remote: error: GH013: Repository rule violations found for refs/heads/main."
        )
        assert 'remote: - Cannot update this protected ref.' in p.stderr
