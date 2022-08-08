import requests
import github as pygithub


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
