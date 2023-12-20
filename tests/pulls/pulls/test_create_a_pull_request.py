import time
from contextlib import suppress
from itertools import islice

import github
import pytest
import requests
from github import GithubException, InputGitTreeElement as item

from ...import pr_payload, check, _fib

def test_basic(repo, config, endpoint, request, users, is_github):
    url, get_hook = endpoint
    h = repo.create_hook("web", {
        'url': url,
        'content_type': 'json',
    }, ['pull_request'], active=True)
    assert get_hook()[0] == 'ping'
    request.addfinalizer(h.delete)

    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    repo.create_git_ref('refs/heads/main2', d_head.sha)
    t = repo.create_git_tree([
        item('foo', '100644', 'blob', 'blorp'),
    ], base_tree=d_head.tree)
    c = repo.create_git_commit("a commit", t, [d_head])
    repo.create_git_ref('refs/heads/create_pr', c.sha)

    with pytest.raises(GithubException) as ghe:
        repo.create_pull("test", "", base=repo.default_branch, head="does-not-exist-69")
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#create-a-pull-request',
        'errors': [{
            'code': 'invalid',
            'field': 'head',
            'resource': 'PullRequest'
        }],
        'message': 'Validation Failed'
    }

    with pytest.raises(GithubException) as ghe:
        repo.create_pull("test", "", base='does-not-exist-68', head="create_pr")
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#create-a-pull-request',
        'errors': [{
            'code': 'invalid',
            'field': 'base',
            'resource': 'PullRequest'
        }],
        'message': 'Validation Failed'
    }

    with pytest.raises(GithubException) as ghe:
        repo.create_pull("test", "", base='does-not-exist-68', head="does-not-exist-69")
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#create-a-pull-request',
        'errors': [{
            'code': 'invalid',
            'field': 'base',
            'resource': 'PullRequest'
        }, {
            'code': 'invalid',
            'field': 'head',
            'resource': 'PullRequest'
        }],
        'message': 'Validation Failed'
    }

    repo_none = users(None).get_repo(repo.full_name)
    with pytest.raises(GithubException) as ghe:
        repo_none.create_pull("test", "", base=repo.default_branch, head="create_pr")
    assert ghe.value.status == 404
    assert ghe.value.data == {
        "message": "Not Found",
        "documentation_url": "https://docs.github.com/rest/pulls/pulls#create-a-pull-request",
    }

    pr = repo.create_pull("test", "", base=repo.default_branch, head="create_pr")
    assert pr.state == 'open'
    assert pr.title == "test"
    assert pr.body is None
    assert pr.base.ref == repo.default_branch
    assert pr.head.ref == 'create_pr'
    assert pr.head.sha == c.sha
    assert pr.head.repo == repo
    assert pr.head.label == f'{repo.owner.login}:create_pr'

    payload = pr_payload(get_hook())
    assert payload['number'] == pr.number
    assert payload['action'] == 'opened'


    with pytest.raises(GithubException) as ghe:
        pr.edit(title='')
    assert pr.title == "test"
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "Validation Failed",
        "errors": [{
            "resource": "PullRequest",
            "code": "missing_field",
            "field": "title"
        }],
        "documentation_url": f"https://docs.github.com/rest/pulls/pulls#update-a-pull-request"
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
    pr.edit(body="test") # behaviour on duplicate

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

    pr.edit(state='poop') # nb: nothing happens (?)
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
        "message": "Validation Failed",
        "errors": [{
            "message": "Proposed base branch 'yeepieyay' was not found",
            "resource": "PullRequest",
            "field": "base",
            "code": "invalid"
        }],
        "documentation_url": f"https://docs.github.com/rest/pulls/pulls#update-a-pull-request"
    }

    p = repo.get_pull(pr.number)
    assert p.title == 'test2'
    assert p.body is None
    assert p.state == 'open'
    assert p.base.ref == 'main2'

    s = requests.Session()
    s.headers['Authorization'] = 'token ' + config['token']
    # pygithub has a check so perform this test directly
    r = s.patch(p.url, json={'title': None})
    assert r.ok, r.json()
    r = s.patch(p.url, json={'title': ''})
    assert r.status_code == 422, r.json()
    assert r.json() == {
        'message': 'Validation Failed',
        'documentation_url': f'https://docs.github.com/rest/pulls/pulls#update-a-pull-request',
        'errors': [{
            'code': 'missing_field',
            'field': 'title',
            'resource': 'PullRequest'
        }],
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
        r = s.patch(p.url, json={} if value is ... else {'body': value})
        res = r.json()
        assert r.ok, res
        assert res['body'] == expected, f"{value} -> {res['body']} != {expected}"

def test_fake_cross_repo(repo, org):
    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    t = repo.create_git_tree([
        item('foo', '100644', 'blob', 'blorp'),
    ], base_tree=d_head.tree)
    c = repo.create_git_commit("a commit", t, [d_head])
    repo.create_git_ref('refs/heads/create_pr_fake', c.sha)

    # use the cross-repo syntax within a repo (madness!)
    pr = repo.create_pull("test", "", base=repo.default_branch, head=f"{org.login}:create_pr_fake")
    assert pr.title == "test"
    assert pr.body is None
    assert pr.head.sha == c.sha
    assert pr.head.repo == repo

def test_cross_repo(request, user, repo):
    # try to create a pr even though we don't have a fork yet
    with pytest.raises(GithubException) as ghe:
        repo.create_pull("cross", "", base=repo.default_branch, head=f'{user.login}:create_pr_cross')
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#create-a-pull-request',
        'errors': [{
            'code': 'invalid',
            'field': 'head',
            'resource': 'PullRequest'
        }],
        'message': 'Validation Failed'
    }

    f = check(request, repo.create_fork())

    for t in islice(_fib(), 12):
        with suppress(GithubException):
            head = f.get_commit(f'refs/heads/{repo.default_branch}').commit
            break
        time.sleep(t)
    else:
        raise AssertionError(f"Never saw refs/heads/{repo.default_branch}")

    t = f.create_git_tree([
        item('foo', '100644', 'blob', 'blorp'),
    ], base_tree=head.tree)
    c = f.create_git_commit("a commit", t, [head])
    f.create_git_ref('refs/heads/create_pr_cross', c.sha)

    pr = repo.create_pull("cross", "", base=repo.default_branch, head=f'{user.login}:create_pr_cross')
    assert pr.head.sha == c.sha
    assert pr.head.repo != repo

def test_from_issue(repo):
    issue = repo.create_issue("an issue")
    with pytest.raises(GithubException) as ghe:
        repo.get_pull(issue.number)
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/pulls/pulls#get-a-pull-request',
        'message': 'Not Found'
    }

    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    t = repo.create_git_tree([
        item('foo', '100644', 'blob', 'blorp'),
    ], base_tree=d_head.tree)
    c = repo.create_git_commit("a commit", t, [d_head])
    repo.create_git_ref('refs/heads/create_pr_from_issue', c.sha)

    pr = repo.create_pull(issue=issue, base=repo.default_branch, head='create_pr_from_issue')
    assert pr.number == issue.number
    assert pr.title == "an issue"
    assert pr.body is None
    assert pr.head.sha == c.sha

def test_create_pr_from_fake(repo):
    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    t = repo.create_git_tree([
        item('foo', '100644', 'blob', 'blorp'),
    ], base_tree=d_head.tree)
    c = repo.create_git_commit("a commit", t, [d_head])
    repo.create_git_ref('refs/heads/create_pr_from_fake', c.sha)

    fake_issue = github.Issue.Issue(None, None, {'number': 9999}, True)
    with pytest.raises(GithubException) as ghe:
        repo.create_pull(issue=fake_issue, base=repo.default_branch, head='create_pr_from_fake')
    assert ghe.value.status == 422 # not 404, go figure...
    assert ghe.value.data == {
        "message": "The specified issue does not exist.",
        "errors": [{
            "value": 9999,
            "resource": "PullRequest",
            "field": "issue",
            "code": "invalid"
        }],
        "documentation_url": "https://docs.github.com/rest/pulls/pulls#create-a-pull-request"
    }

def test_create_pr_from_pr(repo):
    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit
    t = repo.create_git_tree([
        item('foo', '100644', 'blob', 'blorp'),
    ], base_tree=d_head.tree)
    c = repo.create_git_commit("a commit", t, [d_head])
    repo.create_git_ref('refs/heads/create_pr_from_pr', c.sha)

    pr1 = repo.create_pull("title", "", base=repo.default_branch, head='create_pr_from_pr')

    t = repo.create_git_tree([
        item("bar", "100644", "blob", "wheee")
    ], base_tree=d_head.tree)
    c = repo.create_git_commit("an other commit", t, [d_head])
    repo.create_git_ref('refs/heads/create_pr_from_pr2', c.sha)

    with pytest.raises(GithubException) as ghe:
        repo.create_pull(issue=pr1.as_issue(), base=repo.default_branch, head='create_pr_from_pr2')
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "The specified issue is already attached to a pull request.",
        "errors": [{
            "value": pr1.number,
            "resource": "PullRequest",
            "field": "issue",
            "code": "invalid"
        }],
        "documentation_url": "https://docs.github.com/rest/pulls/pulls#create-a-pull-request"
    }


