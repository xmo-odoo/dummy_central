import hashlib
import itertools
import requests
import pytest


@pytest.fixture(scope="module")
def init(repo):
    return repo.get_commit(f'refs/heads/{repo.default_branch}').commit


def test_empty(repo, init):
    desc = repo.create_git_commit(message="test empty", tree=init.tree, parents=[init])

    assert desc.tree == init.tree


def test_unlogged(repo, init):
    r = requests.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
            "tree": init.tree.sha,
        },
    )
    assert r.status_code == 401, r.text
    assert r.json() == {
        "status": '401',
        "message": "Requires authentication",
        "documentation_url": "https://docs.github.com/rest",
    }


def param(date, code, result, msg, marks=()):
    return pytest.param(date, code, result, msg, id=date, marks=marks)


@pytest.mark.parametrize(
    "date,code,result,msg",
    [
        param(
            "1932-11-02T15:05:10+08:00",
            201,
            '1970-01-01T00:00:00Z',
            "apparently github clamps dates before epoch",
        ),
        param(
            "4728-11-02T15:05:10",
            422,
            {
                "status": '422',
                "message": "Invalid request.\n\n4728-11-02T15:05:10 is not a valid date-time.",
                "documentation_url": "https://docs.github.com/rest/git/commits#create-a-commit",
            },
            "non-RFC3339 are invalid",
        ),
        param(
            "2038-01-19T03:14:07Z", 201, "2038-01-19T03:14:07Z", "last valid y2038 date"
        ),
        param(
            "2038-01-19T03:14:08Z",
            201,
            "2038-01-19T03:14:08Z",
            "github timestamps are u32",
        ),
        param(
            "2099-12-31T23:59:59Z",
            201,
            "2099-12-31T23:59:59Z",
            "last second of the 21st century",
        ),
        param(
            "2100-01-01T00:00:00Z",
            201,
            "2100-01-01T00:00:00Z",
            "first second of the 22nd century",
            pytest.mark.skip(reason="github 500s after the 21st century"),
        ),
        param(
            "2106-02-07T06:28:15Z",
            201,
            "2106-02-07T06:28:15Z",
            "last valid y2106 date",
            pytest.mark.skip(reason="github 500s after the 21st century"),
        ),
        param(
            "2106-02-07T06:28:16Z",
            201,
            '1970-01-01T00:00:00Z',
            "y2106 overflow",
            pytest.mark.skip(reason="github 500s after the 21st century"),
        ),
        param(
            "4728-11-02T15:05:10+08:00",
            201,
            '2006-10-17T21:39:50Z',
            "dates above limit get modded'd back in",
            pytest.mark.skip(reason="github 500s after the 21st century"),
        ),
    ],
)
def test_date_range(session, repo, init, date, code, result, msg):
    r = session.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
            "tree": init.tree.sha,
            "author": {
                "name": "Bob",
                "email": "builder@example.org",
                "date": date,
            },
        },
    )
    assert r.status_code == code, r.text
    match result:
        case str():  # adjusted date
            assert r.json()['author']['date'] == result, msg
        case _:  # error dict
            assert r.json() == result, msg


def test_date_zone(session, repo, init):
    r = session.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
            "tree": init.tree.sha,
            "author": {
                "name": "Bob",
                "email": "builder@example.org",
                "date": "1972-11-02T15:05:10+08:00",
            },
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()['author']['date'] == '1972-11-02T07:05:10Z', (
        "apparently github normalizes all timezones to UTC over the API"
        " but e.g. .patch shows the correct author date w/ offset"
    )


@pytest.mark.parametrize(
    "author",
    [
        None,
        *(
            {"name": n, "email": e}
            for n, e in itertools.product(
                [None, "", "Bob"],
                [None, "", "bob@bob.bob"],
            )
            if not (n and e)
        ),
    ],
)
def test_author(session, repo, init, author):
    if author is None:
        errors = {}
        m = "Invalid request.\n\nFor 'properties/author', nil is not an object."
    elif keys := [k for k, v in author.items() if v is None]:
        errors = {}
        m = "Invalid request.\n%s" % ''.join(
            f"\nFor 'properties/{k}', nil is not a string." for k in sorted(keys)
        )
    elif keys := [k for k, v in author.items() if not v]:
        m = "Validation Failed"
        errors = {
            'errors': [
                {'code': 'missing_field', 'field': k, 'resource': 'author'}
                for k in keys
            ]
        }

    r = session.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
            "tree": init.tree.sha,
            "author": author,
        },
    )
    assert r.status_code == 422, r.text
    assert r.json() == {
        "status": '422',
        "message": m,
        **errors,
        "documentation_url": "https://docs.github.com/rest/git/commits#create-a-commit",
    }


# TODO: committer=None and author
# TODO: committer but !author


def test_missing_tree(session, repo):
    r = session.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
        },
    )
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/git/commits#create-a-commit',
        'message': 'Invalid request.\n\n"tree" wasn\'t supplied.',
    }
    r = session.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
            "tree": None,
        },
    )
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/git/commits#create-a-commit',
        'message': "Invalid request.\n\nFor 'properties/tree', nil is not a string.",
    }


INVALID_HASH = hashlib.sha1(b"lol").hexdigest()


def test_invalid_tree(session, repo):
    r = session.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
            "tree": INVALID_HASH,
        },
    )
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/git/commits#create-a-commit',
        'message': 'Tree SHA does not exist',
    }
    r = session.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
            "tree": "nonsense",
        },
    )
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/git/commits#create-a-commit',
        'message': 'The tree parameter must be exactly 40 characters and contain only [0-9a-f].',
    }


def test_invalid_parent(session, repo, init):
    # not sure why this just crashes, but in that case we don't want to test the error handling
    # r = session.post(f'{repo.url}/git/commits', json={
    #     "message": "test",
    #     "tree": init.tree.sha,
    #     "parents": ["nonsense"]
    # })
    # assert r.status_code == 500
    # assert r.text == ""

    r = session.post(
        f'{repo.url}/git/commits',
        json={"message": "test", "tree": init.tree.sha, "parents": [INVALID_HASH]},
    )
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/git/commits#create-a-commit',
        'message': 'Parent SHA does not exist or is not a commit object',
    }

    r = session.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
            "tree": init.tree.sha,
            "parents": [init.sha, INVALID_HASH],
        },
    )
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/git/commits#create-a-commit',
        'message': 'Parent SHA does not exist or is not a commit object',
    }


def test_invalid_parents(session, repo, init):
    r = session.post(
        f'{repo.url}/git/commits',
        json={
            "message": "test",
            "tree": init.tree.sha,
            "parents": [
                INVALID_HASH,
                hashlib.sha1(b"lol2").hexdigest(),
            ],
        },
    )
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        'documentation_url': 'https://docs.github.com/rest/git/commits#create-a-commit',
        'message': 'Parent SHA does not exist or is not a commit object',
    }
