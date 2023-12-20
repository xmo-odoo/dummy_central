import github as gh
import pytest

from ... import check


def test_create_no_user(pytestconfig, request):
    with pytest.raises(gh.GithubException) as ghe:
        check(request, gh.Github(base_url=pytestconfig.getoption('--base-url'))
              .get_user()
              .create_repo(__name__))
    assert ghe.value.status == 401
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/repos/repos#create-a-repository-for-the-authenticated-user',
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
        'documentation_url': 'https://docs.github.com/rest/repos/repos#create-an-organization-repository',
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
        'documentation_url': 'https://docs.github.com/rest/repos/repos#get-a-repository',
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
        'documentation_url': 'https://docs.github.com/rest/repos/repos#create-a-repository-for-the-authenticated-user',
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
        'documentation_url': 'https://docs.github.com/rest/repos/repos#create-an-organization-repository',
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
        "documentation_url": "https://docs.github.com/rest/repos/repos#create-a-repository-for-the-authenticated-user"
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
        "documentation_url": "https://docs.github.com/rest/repos/repos#create-an-organization-repository"
    }
