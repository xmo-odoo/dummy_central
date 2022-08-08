import secrets
import github as gh
import pytest

from ... import check


def test_create_no_user(pytestconfig, request):
    with pytest.raises(gh.GithubException) as ghe:
        check(
            request,
            gh.Github(base_url=pytestconfig.getoption('--base-url'))
            .get_user()
            .create_repo(__name__),
        )
    assert ghe.value.status == 401
    assert ghe.value.data == {
        'status': '401',
        'documentation_url': 'https://docs.github.com/rest/repos/repos#create-a-repository-for-the-authenticated-user',
        'message': 'Requires authentication',
    }


def test_create_no_org(pytestconfig, request, github):
    base_url = pytestconfig.getoption('--base-url')
    # FIXME: create requester by hand instead?
    req = github._Github__requester
    org = gh.Organization.Organization(
        req,
        {},
        {'url': f'{base_url}/orgs/absolutely-probably-doesnt-exist-420'},
        completed=False,
    )

    with pytest.raises(gh.GithubException) as ghe:
        check(request, org.create_repo(__name__))

    assert ghe.value.status == 404
    assert ghe.value.data == {
        'status': '404',
        'documentation_url': 'https://docs.github.com/rest/repos/repos#create-an-organization-repository',
        'message': 'Not Found',
    }


@pytest.mark.parametrize(
    "suffix,result",
    [
        ('.git', ''),
        ('.zip', '.zip'),
        ('.tar.gz', '.tar.gz'),
        ('.jpeg', '.jpeg'),
        ('.git.git', ''),
        ('.jpeg.git', '.jpeg'),
        ('.git.jpeg', '.git.jpeg'),
        ('.gⅈit', '.g-it'),
        ('.gitⅈ', '.git-'),
    ],
)
def test_create_suffix_stripping(request, org, suffix, result):
    name = secrets.token_hex(8)
    r = check(request, org.create_repo(name + suffix))
    assert r.name == name + result


def test_create_invalid_characters(request, user, org):
    """Per https://github.com/isiahmeadows/github-limits#repository-names a
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
        'status': '404',
        'documentation_url': 'https://docs.github.com/rest/repos/repos#get-a-repository',
        'message': 'Not Found',
    }

    r = check(request, org.create_repo("abc;def%()ghi!"))
    assert r.name == 'abc-def-ghi-', "gh replaces runs of invalid characters"

    r = check(request, user.create_repo('a' + '𑣐' * 150 + 'z'))
    assert r.name == 'a-z', "gh's replacement is codepoints-wise"

    # Åström, precomposed
    r = check(request, user.create_repo('\u00c5str\u00f6m'))
    assert r.name == '-str-m', "replaces precomposed characters"
    # Åström, decomposed
    r = check(request, user.create_repo('A\u030astro\u0308m'))
    assert r.name == 'A-stro-m', "replaces only combining characters"


def test_create_too_long(request, user, org):
    """Per https://github.com/isiahmeadows/github-limits#repository-names
    a repository name can not go beyond 100 chars.
    """
    check(request, user.create_repo("z" * 100))

    r = check(request, user.create_repo("z" * 99 + '.git'))
    assert r.name == "z" * 99

    with pytest.raises(gh.GithubException) as ghe:
        check(request, user.create_repo("z" * 101))

    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/repos/repos#create-a-repository-for-the-authenticated-user',
        'message': "Repository creation failed.",
        'errors': [
            {
                'code': 'custom',
                'field': 'name',
                'message': "name cannot be more than 100 characters",
                'resource': "Repository",
            }
        ],
    }

    with pytest.raises(gh.GithubException) as ghe:
        check(request, org.create_repo("z" * 101))

    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/repos/repos#create-an-organization-repository',
        'message': "Repository creation failed.",
        'errors': [
            {
                'code': 'custom',
                'field': 'name',
                'message': "name cannot be more than 100 characters",
                'resource': "Repository",
            }
        ],
    }


def test_duplicate(request, user):
    check(request, user.create_repo(__name__))
    with pytest.raises(gh.GithubException) as ghe:
        check(request, user.create_repo(__name__))

    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        "message": "Repository creation failed.",
        "errors": [
            {
                "resource": "Repository",
                "code": "custom",
                "field": "name",
                "message": "name already exists on this account",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/repos/repos#create-a-repository-for-the-authenticated-user",
    }


def test_duplicate_org(request, org):
    check(request, org.create_repo(__name__))
    with pytest.raises(gh.GithubException) as ghe:
        check(request, org.create_repo(__name__))

    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        "message": "Repository creation failed.",
        "errors": [
            {
                "resource": "Repository",
                "code": "custom",
                "field": "name",
                "message": "name already exists on this account",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/repos/repos#create-an-organization-repository",
    }
