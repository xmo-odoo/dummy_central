import base64
import contextlib
import os
import time
from contextlib import suppress
from itertools import islice

import github
import pytest
import requests
from github import GithubException, InputGitTreeElement as item

from ... import pr_payload, check, _fib, safe_delete


def test_basic(repo, session, endpoint, request, users, is_github, genbranch):
    url, get_hook = endpoint
    h = repo.create_hook(
        "web",
        {
            'url': url,
            'content_type': 'json',
        },
        ['pull_request'],
        active=True,
    )
    assert get_hook()[0] == 'ping'
    request.addfinalizer(h.delete)

    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    repo.create_git_ref('refs/heads/main2', d_head.sha)
    t = repo.create_git_tree(
        [
            item('foo', '100644', 'blob', 'blorp'),
        ],
        base_tree=d_head.tree,
    )
    c = repo.create_git_commit("a commit", t, [d_head])
    branchname = genbranch()
    repo.create_git_ref(f'refs/heads/{branchname}', c.sha)

    with pytest.raises(GithubException) as ghe:
        repo.create_pull(repo.default_branch, "does-not-exist-69", title="test")
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#create-a-pull-request',
        'errors': [{'code': 'invalid', 'field': 'head', 'resource': 'PullRequest'}],
        'message': 'Validation Failed',
    }

    with pytest.raises(GithubException) as ghe:
        repo.create_pull('does-not-exist-68', branchname, title="test")
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#create-a-pull-request',
        'errors': [{'code': 'invalid', 'field': 'base', 'resource': 'PullRequest'}],
        'message': 'Validation Failed',
    }

    with pytest.raises(GithubException) as ghe:
        repo.create_pull('does-not-exist-68', "does-not-exist-69", title="test")
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#create-a-pull-request',
        'errors': [
            {'code': 'invalid', 'field': 'base', 'resource': 'PullRequest'},
            {'code': 'invalid', 'field': 'head', 'resource': 'PullRequest'},
        ],
        'message': 'Validation Failed',
    }

    repo_none = users(None).get_repo(repo.full_name)
    with pytest.raises(GithubException) as ghe:
        repo_none.create_pull(repo.default_branch, branchname, title="test")
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'status': '404',
        "message": "Not Found",
        "documentation_url": "https://docs.github.com/rest/pulls/pulls#create-a-pull-request",
    }

    pr = repo.create_pull(repo.default_branch, branchname, title="test")
    assert pr.state == 'open'
    assert pr.title == "test"
    assert pr.body is None
    assert pr.base.ref == repo.default_branch
    assert pr.head.ref == branchname
    assert pr.head.sha == c.sha
    assert pr.head.repo == repo
    assert pr.head.label == f'{repo.owner.login}:{branchname}'

    payload = pr_payload(get_hook())
    assert payload['number'] == pr.number
    assert payload['action'] == 'opened'

    with pytest.raises(GithubException) as ghe:
        pr.edit(title='')
    assert pr.title == "test"
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        "message": "Validation Failed",
        "errors": [
            {"resource": "PullRequest", "code": "missing_field", "field": "title"}
        ],
        "documentation_url": "https://docs.github.com/rest/pulls/pulls#update-a-pull-request",
    }

    # immediately test webhook, helps delaying actions
    pr.edit(title="test2")
    assert pr.title == "test2"
    payload = pr_payload(get_hook())
    assert payload['action'] == 'edited', payload
    assert payload['changes'] == {'title': {'from': 'test'}}, payload
    assert payload['pull_request']['title'] == 'test2', payload
    # apparently never triggers a webhook because no actual change
    pr.edit(title="test2")

    pr.edit(body="test")
    assert pr.body == "test"
    payload = pr_payload(get_hook())
    assert payload['action'] == 'edited', payload
    assert payload['changes'] == {'body': {'from': ''}}, payload
    assert payload['pull_request']['body'] == 'test', payload
    # see above, no-ops don't trigger webhooks
    pr.edit(body="test")  # behaviour on duplicate

    pr.edit(body='')
    assert pr.body is None
    payload = pr_payload(get_hook())
    assert payload['action'] == 'edited', payload
    assert payload['changes'] == {'body': {'from': 'test'}}, payload
    assert payload['pull_request']['body'] is None, payload

    pr.edit(state='closed')
    assert pr.state == 'closed'
    payload = pr_payload(get_hook())
    assert payload['action'] == 'closed', payload

    pr.edit(state='open')
    assert pr.state == 'open'
    payload = pr_payload(get_hook())
    assert payload['action'] == 'reopened', payload

    pr.edit(state='poop')  # nb: nothing happens (?)
    pr.edit(base='main2')
    assert pr.base.ref == 'main2'
    payload = pr_payload(get_hook())
    assert payload['action'] == 'edited', payload
    assert payload['changes'] == {
        'base': {
            'ref': {'from': repo.default_branch},
            'sha': {'from': d_head.sha},
        }
    }, payload
    assert payload['pull_request']['base']['ref'] == 'main2', payload

    # make not enabled anymore so the other editions don't trigger
    # hooks which interfere with later tests
    h.edit("", {}, active=False)

    with pytest.raises(GithubException) as ghe:
        pr.edit(base='yeepieyay')
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        "message": "Validation Failed",
        "errors": [
            {
                "message": "Proposed base branch 'yeepieyay' was not found",
                "resource": "PullRequest",
                "field": "base",
                "code": "invalid",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/pulls/pulls#update-a-pull-request",
    }

    p = repo.get_pull(pr.number)
    assert p.title == 'test2'
    assert p.body is None
    assert p.state == 'open'
    assert p.base.ref == 'main2'

    # pygithub has a check so perform this test directly
    r = session.patch(p.url, json={'title': None})
    assert r.ok, r.json()
    r = session.patch(p.url, json={'title': ''})
    assert r.status_code == 422, r.json()
    assert r.json() == {
        "status": "422",
        'message': 'Validation Failed',
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#update-a-pull-request',
        'errors': [
            {'code': 'missing_field', 'field': 'title', 'resource': 'PullRequest'}
        ],
    }

    # pygithub can't sim it but there are really 3 different possibilities for
    # a field being "not set"
    #
    # - missing
    # - set to null (None)
    # - set to empty
    #
    # for pr update missing means "don't change", but `None` diverges:
    # for titles it means "no change", but for bodies it means "set to
    # empty"
    sentinel = 'Melek Yehudayai'
    for value, expected in [(..., sentinel), (None, None), ('', None)]:
        p.edit(body=sentinel)
        r = session.patch(p.url, json={} if value is ... else {'body': value})
        res = r.json()
        assert r.ok, res
        assert res['body'] == expected, f"{value} -> {res['body']} != {expected}"


def test_fake_cross_repo(repo, org, genbranch):
    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    t = repo.create_git_tree(
        [
            item('foo', '100644', 'blob', 'blorp'),
        ],
        base_tree=d_head.tree,
    )
    c = repo.create_git_commit("a commit", t, [d_head])
    branchname = genbranch()
    repo.create_git_ref(f'refs/heads/{branchname}', c.sha)

    # use the cross-repo syntax within a repo (madness!)
    pr = repo.create_pull(
        repo.default_branch, f"{org.login}:{branchname}", title="test"
    )
    assert pr.title == "test"
    assert pr.body is None
    assert pr.head.sha == c.sha
    assert pr.head.repo == repo


def test_cross_repo(request, user, repo, genbranch):
    branchname = genbranch()
    # try to create a pr even though we don't have a fork yet
    with pytest.raises(GithubException) as ghe:
        repo.create_pull(
            repo.default_branch, f'{user.login}:{branchname}', title="cross"
        )
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#create-a-pull-request',
        'errors': [{'code': 'invalid', 'field': 'head', 'resource': 'PullRequest'}],
        'message': 'Validation Failed',
    }

    f = check(request, repo.create_fork())

    for t in islice(_fib(), 12):
        with suppress(GithubException):
            head = f.get_commit(f'refs/heads/{repo.default_branch}').commit
            break
        time.sleep(t)
    else:
        raise AssertionError(f"Never saw refs/heads/{repo.default_branch}")

    t = f.create_git_tree(
        [
            item('foo', '100644', 'blob', 'blorp'),
        ],
        base_tree=head.tree,
    )
    c = f.create_git_commit("a commit", t, [head])
    f.create_git_ref(f'refs/heads/{branchname}', c.sha)

    pr = repo.create_pull(
        repo.default_branch, f'{user.login}:{branchname}', title="cross"
    )
    assert pr.head.sha == c.sha
    assert pr.head.repo != repo


def test_from_issue(repo, genbranch):
    issue = repo.create_issue("an issue")
    with pytest.raises(GithubException) as ghe:
        repo.get_pull(issue.number)
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'status': '404',
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#get-a-pull-request',
        'message': 'Not Found',
    }

    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    t = repo.create_git_tree(
        [
            item('foo', '100644', 'blob', 'blorp'),
        ],
        base_tree=d_head.tree,
    )
    c = repo.create_git_commit("a commit", t, [d_head])
    branchname = genbranch()
    repo.create_git_ref(f'refs/heads/{branchname}', c.sha)

    pr = repo.create_pull(repo.default_branch, branchname, issue=issue)
    assert pr.number == issue.number
    assert pr.title == "an issue"
    assert pr.body is None
    assert pr.head.sha == c.sha


def test_create_pr_from_fake(repo, genbranch):
    branchname = genbranch()
    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    t = repo.create_git_tree(
        [
            item('foo', '100644', 'blob', 'blorp'),
        ],
        base_tree=d_head.tree,
    )
    c = repo.create_git_commit("a commit", t, [d_head])
    repo.create_git_ref(f'refs/heads/{branchname}', c.sha)

    fake_issue = github.Issue.Issue(d._requester, None, {'number': 9999}, True)
    with pytest.raises(GithubException) as ghe:
        repo.create_pull(repo.default_branch, branchname, issue=fake_issue)
    assert ghe.value.status == 422  # not 404, go figure...
    assert ghe.value.data == {
        "status": '422',
        "message": "The specified issue does not exist.",
        "errors": [
            {
                "value": 9999,
                "resource": "PullRequest",
                "field": "issue",
                "code": "invalid",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/pulls/pulls#create-a-pull-request",
    }


def test_create_pr_from_pr(repo, genbranch):
    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    t = repo.create_git_tree(
        [
            item('foo', '100644', 'blob', 'blorp'),
        ],
        base_tree=d_head.tree,
    )
    c = repo.create_git_commit("a commit", t, [d_head])
    branchname = genbranch()
    repo.create_git_ref(f'refs/heads/{branchname}', c.sha)

    pr1 = repo.create_pull(repo.default_branch, branchname, title="test")

    t = repo.create_git_tree(
        [item("bar", "100644", "blob", "wheee")], base_tree=d_head.tree
    )
    c = repo.create_git_commit("an other commit", t, [d_head])
    branchname = genbranch()
    repo.create_git_ref(f'refs/heads/{branchname}', c.sha)

    with pytest.raises(GithubException) as ghe:
        repo.create_pull(repo.default_branch, branchname, issue=pr1.as_issue())
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        "message": "The specified issue is already attached to a pull request.",
        "errors": [
            {
                "value": pr1.number,
                "resource": "PullRequest",
                "field": "issue",
                "code": "invalid",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/pulls/pulls#create-a-pull-request",
    }


@pytest.fixture(scope="module")
def _repos(request, users, org, repo):
    """Mapping of users (ish) to repos, created upfront"""
    assert repo.organization.login == org.login

    with contextlib.ExitStack() as exit:
        repo_a = users('a').get_user().create_repo("a_repo", auto_init=True)
        exit.callback(safe_delete, repo_a)
        repo_c = users('c').get_user().create_repo("c_repo", auto_init=True)
        exit.callback(safe_delete, repo_c)
        repos = {None: repo, 'a': repo_a, 'c': repo_c}

        for r in repos.values():
            t = r.create_git_tree(
                [
                    item("a", "100644", "blob", "blorp"),
                ]
            )
            c = r.create_git_commit("thing", tree=t, parents=[])
            r.create_git_ref("refs/heads/mcm", c.sha)

        yield repos


@pytest.fixture
def source_repo(request, _repos):
    return _repos[request.param]


def random_id(*, prefix="", n):
    return prefix + base64.b32encode(os.urandom(n)).decode().rstrip('=')


@pytest.mark.skip(
    reason="Feature is basically useless, last case is broken "
    "and getting the test to work reliably is a pain in the ass"
)
@pytest.mark.parametrize(
    "source_repo,username,flag",
    [
        # org internal
        (None, None, True),
        # user internal
        ("c", "c", False),
        # user to user
        ("c", "a", True),
        # user to org
        (None, "c", True),
        # org to user, the flag is a lie because it doesn't actually work
        ("c", None, True),
    ],
    indirect=['source_repo'],
)
def test_maintainer_can_modify(
    request,
    config,
    org,
    users,
    source_repo,
    username,
    flag,
):
    """Tests the default behaviour of the `maintainer_can_modify`

    - `source_repo` should have a branch mcm
    - `username` forks the repository (maybe)
    - some shit is added in the fork
    - a PR is created against the source_repo:mcm
    - check if the flag is enabled

    This setting seems to be hella confused as "mantainer_can_modify" is not
    actually supported on repos from orgs (orgs/community#5634), need to
    investigate in an interactive session.
    """
    b = source_repo.get_branch("mcm").commit.commit
    forker = users(username or 'base')
    source_repo = forker.get_repo(source_repo.full_name)
    if source_repo.owner.login == username:
        fork = source_repo
    else:
        fork = check(
            request,
            source_repo.create_fork(
                github.GithubObject.NotSet if username else org, name=random_id(n=6)
            ),
        )

    t = fork.create_git_tree([item("b", "100644", "blob", "blorp")])
    c = fork.create_git_commit("thing2", tree=t, parents=[b])
    branch = random_id(n=6)
    fork.create_git_ref(f"refs/heads/{branch}", c.sha)

    head = f"{fork.owner.login}:{branch}"
    # PyGithub/PyGithub#2942 create_pull does not support head_repo
    # pr = source_repo.create_pull("mcm", head, title="bleh", head_repo=fork)
    r = requests.post(
        f"{source_repo.url}/pulls",
        headers={
            "Authorization": "token {}".format(config['users'][username or 'base'])
        },
        json={
            "title": "bleh",
            "head": head,
            "head_repo": fork.full_name,
            "base": "mcm",
        },
    )
    assert r.ok, r.text
    pr = r.json()

    assert pr['maintainer_can_modify'] == flag
