import github as pygithub
import pytest
import requests


def test_create_with_number(
    session: requests.Session,
    repo: pygithub.Repository,
) -> None:
    url = repo.issues_url.replace('{/number}', '')
    r = session.post(
        url,
        json={
            "title": 59437,
        },
    )
    assert r.ok, r.text
    assert r.json()['title'] == '59437'
    assert r.json()['body'] is None

    r = session.post(
        url,
        json={
            "title": -59437,
            "body": "a body",
        },
    )
    assert r.ok, r.text
    assert r.json()['title'] == '-59437'
    assert r.json()['body'] == 'a body'

    r = session.post(
        url,
        json={
            "title": "foo",
            "body": 42,
        },
    )
    assert not r.ok, r.text
    # contingent on either configurable serde error reporting,
    # or deserializing to Value, then validating, then converting to DTO
    # assert r.status_code == 422
    # assert r.json() == {
    #     "message":"Invalid request.\n\nFor 'properties/body', 42 is not a string or null.",
    #     "documentation_url":"https://docs.github.com/rest/issues/issues#create-an-issue",
    #     "status":"422",
    # }


def test_create_empty_body(repo: pygithub.Repository) -> None:
    i1 = repo.create_issue(title="foo")
    assert i1.body is None
    i2 = repo.create_issue(title="foo", body="")
    assert i2.body is None


def test_create_long_body(repo: pygithub.Repository) -> None:
    i = repo.create_issue(title="foo", body="a" * 65536)
    assert i.body == "a" * 65536
    with pytest.raises(pygithub.GithubException) as ghe:
        repo.create_issue(title="foo", body="a" * 65537)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/issues/issues#create-an-issue',
        'errors': [
            {
                'code': 'invalid',
                'field': 'body',
                'message': 'body is too long (maximum is 65536 characters)',
                'resource': 'Issue',
                'value': None,
            }
        ],
        'message': 'Validation Failed',
        'status': '422',
    }
