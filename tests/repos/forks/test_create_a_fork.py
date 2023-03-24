import github as gh
import pytest

from ... import check, safe_delete


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
    repo = check(request, org.create_repo(__name__, auto_init=True))
    # here the default_branch should be the org's default_branch
    repo.create_git_ref(
        "refs/heads/xxx",
        repo.get_branch(repo.default_branch).commit.sha
    )
    repo.edit(default_branch="xxx")
    assert repo.default_branch == "xxx"

    # TODO: fork the fork to see if parent and source do diverge as we think
    f = check(request, repo.create_fork())
    assert f.full_name == f'{user.login}/{__name__}'
    assert f.parent == f.source == repo
    assert f.fork is True
    # WTF apparently the fork resets the default_branch to the user's? What?
    # assert f.default_branch == "xxx"

    f2 = repo.create_fork()
    assert f2.full_name == f.full_name,\
        "forking twice into a user's account is a no-op"

    with pytest.raises(gh.GithubException) as ghe:
        check(request, repo.create_fork(user.login))
    assert ghe.value.status == 422,\
        "can't explicitely fork in a user's account, only implicitly in current"
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

# FIXME: https://github.blog/changelog/2022-06-27-improved-innersource-collaboration-and-enterprise-fork-policies/
#
# -> can now fork a repo from an org to the same org, and thus likely fork the
#    same base to multiple, different, repositories within an org.
def test_fork_to_org(request, user, org):
    repo = check(request, user.create_repo(__name__, auto_init=True))

    with pytest.raises(gh.GithubException) as ghe:
        org.get_repo(__name__)
    assert ghe.value.status == 404, "the org should not have a test repo"

    f = check(request, repo.create_fork(org.login))
    assert f.full_name == f'{org.login}/{__name__}'
    # f2 = repo.create_fork(org.login)
    # assert f2 == f
    # assert f2.full_name == f.full_name

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
    repo = check(request, user.create_repo(__name__, auto_init=True))

    existing = check(request, org.create_repo(__name__))
    assert existing.full_name == f'{org.login}/{__name__}'
    new = check(request, repo.create_fork(org.login))
    assert new.full_name == f'{org.login}/{__name__}-1', "should have renamed the fork"
    # FIXME: see above
    # refork = repo.create_fork(org.login)
    # assert refork.full_name == new.full_name, "refork should land in the same place"

def test_fork_from_org_already_exists(request, user, org):
    repo = check(request, org.create_repo(__name__, auto_init=True))

    existing = check(request, user.create_repo(__name__))
    assert existing.full_name == f'{user.login}/{__name__}'
    new = check(request, repo.create_fork())
    assert new.full_name == f'{user.login}/{__name__}-1', "should have renamed the fork"
    refork = repo.create_fork()
    assert refork.full_name == new.full_name, "refork should land in the same place"

def test_fork_self(request, user, org):
    repo = check(request, user.create_repo(__name__, auto_init=True))
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
    repo = check(request, org.create_repo(__name__, auto_init=True))

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
    repo = check(request, org.create_repo(f'{__name__}-1', auto_init=True))

    r = check(request, repo.create_fork(), delete=False)
    assert r.full_name == f'{user.login}/{__name__}-1'
    safe_delete(r)

    whoops = check(request, user.create_repo(f'{__name__}-1'))
    assert whoops.full_name == f'{user.login}/{__name__}-1'

    new = check(request, repo.create_fork())
    assert new.full_name == f'{user.login}/{__name__}-2', "should have renamed the fork"

    repo = check(request, org.create_repo('{__name__}-9', auto_init=True))
    check(request, user.create_repo('{__name__}-9'))
    f = check(request, repo.create_fork())
    assert f.full_name, f'{user.login}/{__name__}-10'

def test_fork_unauth(pytestconfig, request, user, org):
    repo = check(request, user.create_repo(__name__, auto_init=True))

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
