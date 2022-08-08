"""This file validates github's behaviour for operations related to the
repositories themselves.
"""
import time

import github as gh
import pytest
import requests

def safe_delete(r):
    err = None
    for i in range(5):
        try:
            r.delete()
        except gh.GithubException as e:
            if e.status == 403:
                err = e
                # can't delete yet
                time.sleep(5)
                continue

            if e.status == 404:
                return

            raise
    raise err

# FIXME: this should remember repos by fullname to avoid double-deleting them
def check(req, r, delete=True):
    token = req.getfixturevalue('config')['token']
    s = requests.Session()
    s.headers['Authorization'] = f'token {token}'
    # wait up to ~2.5mn
    for t in [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]:
        time.sleep(t)
        if s.head(r.url).ok:
            if delete:
                req.addfinalizer(lambda: safe_delete(r))
            return r
    raise Exception(f"Never saw repository {r.url!r}")

def test_create_init(request, user, org):
    # TODO: should probably have an entire file dedicated to how wonky
    # and inconsistent the contents API is
    r = check(request, user.create_repo(__name__))
    # can't test default branch: the repository's default branch is
    # copied from the user's, but there's (apparently) no API to get
    # or set the user's default branch
    #assert r.default_branch == "main"
    assert r.size == 0
    r.create_file(path="dummy", message="dummy", content="dummy", branch="dummy")
    assert user.get_repo(r.name).default_branch == "dummy",\
        "if the repository is empty, the first create_content updates its default branch"
    with pytest.raises(gh.GithubException) as ghe:
        r.create_file(path="dummy2", message="dummkopf", content="nope", branch="some-other")
    assert ghe.value.status == 404
    assert ghe.value.data == {
        "message": "Branch some-other not found",
        "documentation_url": "https://docs.github.com/rest/reference/repos#create-or-update-file-contents",
    }


def test_create_no_user(pytestconfig, request):
    with pytest.raises(gh.GithubException) as ghe:
        check(request, gh.Github(base_url=pytestconfig.getoption('--base-url'))
              .get_user()
              .create_repo(__name__))
    assert ghe.value.status == 401
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/repos#create-a-repository-for-the-authenticated-user',
        'message': 'Requires authentication'
    }

def test_create_no_org(pytestconfig, request, github):
    base_url = pytestconfig.getoption('--base-url')
    # FIXME: create requester by hand instead?
    req = github._Github__requester
    org = gh.Organization.Organization(req, {}, {
        'url': f'{base_url}/orgs/absolutely-probably-doesnt-exist-420'
    }, completed=False)

    with pytest.raises(gh.GithubException) as ghe:
        check(request, org.create_repo(__name__))

    assert ghe.value.status == 404
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/repos#create-an-organization-repository',
        'message': 'Not Found'
    }

def test_create_invalid_characters(request, user, org):
    """ Per https://github.com/isiahmeadows/github-limits#repository-names a
    github repository name can only contain ASCII letters, numbers, `-`, `_`,
    and `.`.

    Via the UI invalid characters are automatically replaced by `-`, but what
    happens via the API?
    """
    # TODO: what happens with lone surrogates? aka does this work on a codepoint or USV basis?
    r = check(request, user.create_repo("abc;def*_ghi"))
    assert r.name == 'abc-def-_ghi'

    with pytest.raises(gh.GithubException) as ghe:
        user.get_repo('abc;def*_ghi')
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/repos#get-a-repository',
        'message': 'Not Found'
    }

    r = check(request, org.create_repo("abc;def%()ghi!"))
    assert r.name == 'abc-def-ghi-', "gh replaces runs of invalid characters"

    r = check(request, user.create_repo('a' + '𑣐'*150 + 'z'))
    assert r.name == 'a-z', "gh's replacement is codepoints-wise"

    # Åström, precomposed
    r = check(request, user.create_repo('\u00C5str\u00F6m'))
    assert r.name == '-str-m', "replaces precomposed characters"
    # Åström, decomposed
    r = check(request, user.create_repo('A\u030Astro\u0308m'))
    assert r.name == 'A-stro-m', "replaces only combining characters"

def test_create_too_long(request, user, org):
    """ Per https://github.com/isiahmeadows/github-limits#repository-names
    a repository name can not go beyond 100 chars.
    """
    with pytest.raises(gh.GithubException) as ghe:
        check(request, user.create_repo("z"*101))

    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/repos#create-a-repository-for-the-authenticated-user',
        'message': "Repository creation failed.",
        'errors': [{
            'code': 'custom',
            'field': 'name',
            'message': "name is too long (maximum is 100 characters)",
            'resource': "Repository",
        }]
    }

    with pytest.raises(gh.GithubException) as ghe:
        check(request, org.create_repo("z"*101))

    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/repos#create-an-organization-repository',
        'message': "Repository creation failed.",
        'errors': [{
            'code': 'custom',
            'field': 'name',
            'message': "name is too long (maximum is 100 characters)",
            'resource': "Repository",
        }]
    }

def test_duplicate(request, user):
    check(request, user.create_repo(__name__))
    with pytest.raises(gh.GithubException) as ghe:
        check(request, user.create_repo(__name__))

    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "Repository creation failed.",
        "errors": [{
            "resource": "Repository",
            "code": "custom",
            "field": "name",
            "message": "name already exists on this account"
        }],
        "documentation_url": "https://docs.github.com/rest/reference/repos#create-a-repository-for-the-authenticated-user"
    }

def test_duplicate_org(request, org):
    check(request, org.create_repo(__name__))
    with pytest.raises(gh.GithubException) as ghe:
        check(request, org.create_repo(__name__))

    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "Repository creation failed.",
        "errors": [{
            "resource": "Repository",
            "code": "custom",
            "field": "name",
            "message": "name already exists on this account"
        }],
        "documentation_url": "https://docs.github.com/rest/reference/repos#create-an-organization-repository"
    }

def test_fork_empty(request, org):
    repo = check(request, org.create_repo(__name__))
    with pytest.raises(gh.GithubException) as ghe:
        check(request, repo.create_fork())

    assert ghe.value.status == 403
    assert ghe.value.data == {
        "message": "The repository exists, but it contains no Git content. "
                   "Empty repositories cannot be forked.",
        "documentation_url": "https://docs.github.com/rest/reference/repos#create-a-fork"
    }

def test_fork_from_org(request, user, org):
    repo = check(request, org.create_repo(__name__))
    repo.create_file("test.txt", "test", "test", branch="test")

    # go figure...
    with pytest.raises(gh.GithubException) as ghe:
        repo.create_file('test2', 'content', 'great', branch="bob")
    assert ghe.value.status == 404
    assert ghe.value.data == {
        "message": "Branch bob not found",
        "documentation_url": "https://docs.github.com/rest/reference/repos#create-or-update-file-contents"
    }

    # assert repo.default_branch == 'main'
    assert repo.fork is False
    assert repo.parent is None
    assert repo.source is None
    with pytest.raises(gh.GithubException) as ghe:
        repo.edit(default_branch="bob")
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "Validation Failed",
        "errors": [{
            "message": "The branch bob was not found. Please push that ref first or create it via the Git Data API.",
            "resource": "Repository",
            "field": "default_branch",
            "code": "invalid"
        }],
        "documentation_url": "https://docs.github.com/rest/reference/repos#update-a-repository"
    }

    repo.edit(default_branch="test")
    assert repo.default_branch == 'test'

    # TODO: fork the fork to see if parent and source do diverge as we think
    f = check(request, repo.create_fork())
    assert f.full_name == f'{user.login}/{__name__}'
    assert f.parent == f.source == repo
    assert f.fork is True
    # default branch behaviour on fork is unclear, sometimes it stays, others
    # it does not, doesn't seem related to UI v API ¯\_(ツ)_/¯
    # possibly difference in account configuration?
    # assert f.default_branch == "main"
    f2 = repo.create_fork()
    assert f2.full_name == f.full_name

    with pytest.raises(gh.GithubException) as ghe:
        check(request, repo.create_fork(user.login))
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": f"{user.login!r} is the login for a user account. "
                   f"You must pass the login for an organization account.",
        "errors": [{
            "resource": "Fork",
            "code": "invalid",
            "field": "organization"
        }],
        "documentation_url": "https://docs.github.com/rest/reference/repos#create-a-fork"
    }

def test_fork_to_org(request, user, org):
    repo = check(request, user.create_repo(__name__))
    repo.create_file("test.txt", "test", "test", branch="test")

    with pytest.raises(gh.GithubException) as ghe:
        org.get_repo(__name__)
    assert ghe.value.status == 404, "the org should not have a test repo"

    f = check(request, repo.create_fork(org.login))
    assert f.full_name == f'{org.login}/{__name__}'
    f2 = repo.create_fork(org.login)
    assert f2 == f
    assert f2.full_name == f.full_name

    with pytest.raises(gh.GithubException) as ghe:
        check(request, repo.create_fork('reasonably-sure-this-does-not-exist-69'))
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "Validation Failed",
        "errors": [{
            "resource": "Fork",
            "code": "invalid",
            "field": "organization"
        }],
        "documentation_url": "https://docs.github.com/rest/reference/repos#create-a-fork"
    }

def test_fork_to_org_already_exists(request, user, org):
    repo = check(request, user.create_repo(__name__))
    repo.create_file("test.txt", "test", "test", branch="test")

    existing = check(request, org.create_repo(__name__))
    assert existing.full_name == f'{org.login}/{__name__}'
    new = check(request, repo.create_fork(org.login))
    assert new.full_name == f'{org.login}/{__name__}-1', "should have renamed the fork"
    refork = repo.create_fork(org.login)
    assert refork.full_name == new.full_name, "refork should land in the same place"

def test_fork_from_org_already_exists(request, user, org):
    repo = check(request, org.create_repo(__name__))
    repo.create_file("test.txt", "test", "test", branch="test")

    existing = check(request, user.create_repo(__name__))
    assert existing.full_name == f'{user.login}/{__name__}'
    new = check(request, repo.create_fork())
    assert new.full_name == f'{user.login}/{__name__}-1', "should have renamed the fork"
    refork = repo.create_fork()
    assert refork.full_name == new.full_name, "refork should land in the same place"

def test_fork_self(request, user, org):
    repo = check(request, user.create_repo(__name__))
    repo.create_file("test.txt", "test", "test", branch="test")
    new = repo.create_fork()
    assert new == repo

    repo2 = check(request, repo.create_fork(org.login))
    assert repo2.full_name == f'{org.login}/{repo.name}'

    # check what happens in case of cycles / if a fork from the same graph
    # already exists
    repo3 = repo2.create_fork()
    assert repo3 == repo
    assert repo3.parent is None
    assert repo3.source is None

def test_fork_already_exists_extended(request, user, org):
    repo = check(request, org.create_repo(__name__))
    repo.create_file("test.txt", "test", "test", branch="test")

    rs = [
        check(request, user.create_repo(n))
        for n in [__name__, f'{__name__}-1', f'{__name__}-2']
    ]

    new = check(request, repo.create_fork())
    assert new.full_name == f'{user.login}/{__name__}-3', "should have renamed the fork"

    new.edit(name='gloubiboulga')
    assert new.full_name == f'{user.login}/gloubiboulga'

    new2 = repo.create_fork()
    assert new2.full_name == f'{user.login}/gloubiboulga',\
        "should have found the renamed fork"

    for r in rs:
        r.delete()

    new3 = repo.create_fork()
    assert new3.full_name == f'{user.login}/gloubiboulga',\
        "should have found the renamed fork even without conflicts"

def test_fork_suffixed(request, user, org):
    repo = check(request, org.create_repo(f'{__name__}-1'))
    repo.create_file("test.txt", "test", "test", branch="test")

    r = check(request, repo.create_fork(), delete=False)
    assert r.full_name == f'{user.login}/{__name__}-1'
    r.delete()

    whoops = check(request, user.create_repo(f'{__name__}-1'))
    assert whoops.full_name == f'{user.login}/{__name__}-1'

    new = check(request, repo.create_fork())
    # fuck's sake...
    assert new.full_name == f'{user.login}/{__name__}-2', "should have renamed the fork"

    repo = check(request, org.create_repo('{__name__}-9'))
    repo.create_file("test.txt", "test", "test", branch="test")
    check(request, user.create_repo('{__name__}-9'))
    f = check(request, repo.create_fork())
    assert f.full_name, f'{user.login}/{__name__}-10'

def test_fork_unauth(pytestconfig, request, user, org):
    repo = check(request, user.create_repo(__name__))
    repo.create_file("test.txt", "test", "test", branch="test")

    unauth = gh.Github(base_url=pytestconfig.getoption('--base-url')).get_repo(repo.full_name)
    with pytest.raises(gh.GithubException) as ghe:
        unauth.create_fork()
    assert ghe.value.status == 401
    assert ghe.value.data == {
        "message": "You must be logged in to do that.",
        "documentation_url": "https://docs.github.com/rest/guides/getting-started-with-the-rest-api#authentication"
    }
    with pytest.raises(gh.GithubException) as ghe:
        unauth.create_fork(org.login)
    assert ghe.value.status == 401
    assert ghe.value.data == {
        "message": "You must be logged in to do that.",
        "documentation_url": "https://docs.github.com/rest/guides/getting-started-with-the-rest-api#authentication"
    }
