import pytest
from github import GithubException


def event(action, e):
    event, payload = e
    assert event == 'issue_comment'
    assert payload['action'] == action
    if action != 'edited':
        return payload['issue'], payload['comment']
    else:
        return payload['issue'], payload['comment'], payload['changes']


def test_issue_comments(session, repo, pr, endpoint, request, is_github):
    url, get_hook = endpoint
    h = repo.create_hook(
        "web",
        {
            'url': url,
            'content_type': 'json',
        },
        ['issue_comment'],
        active=True,
    )
    assert get_hook()[0] == 'ping'
    request.addfinalizer(h.delete)

    c = pr.create_issue_comment("this is absolute nonsense!")
    issue, comment = event('created', get_hook())
    assert issue['number'] == pr.number
    assert comment['body'] == c.body

    with pytest.raises(GithubException) as ghe:
        pr.get_issue_comment(21345)
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'status': '404',
        'documentation_url': 'https://docs.github.com/rest/issues/comments#get-an-issue-comment',
        'message': 'Not Found',
    }

    assert pr.get_issue_comment(c.id).body == "this is absolute nonsense!"
    c.edit("this is absolute genius!")
    issue, comment, previous = event('edited', get_hook())
    assert issue['number'] == pr.number
    assert previous['body']['from'] == "this is absolute nonsense!"
    assert comment['body'] == "this is absolute genius!"

    pr.create_issue_comment("well that looks odd")
    event('created', get_hook())
    assert [c.body for c in pr.get_issue_comments()] == [
        "this is absolute genius!",
        "well that looks odd",
    ]
    c.delete()

    assert [c.body for c in pr.get_issue_comments()] == ["well that looks odd"]
    # HA HA
    with pytest.raises(GithubException) as ghe:
        c.edit("whoopsie")
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'status': '404',
        'documentation_url': 'https://docs.github.com/rest/issues/comments#update-an-issue-comment',
        'message': 'Not Found',
    }
    with pytest.raises(GithubException) as ghe:
        c.delete()
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'status': '404',
        'documentation_url': 'https://docs.github.com/rest/issues/comments#delete-an-issue-comment',
        'message': 'Not Found',
    }

    issue, comment = event('deleted', get_hook())
    assert issue['number'] == pr.number
    assert comment['body'] == "this is absolute genius!"

    r = session.post(pr.comments_url, json={})
    assert r.status_code == 422, r.text
    assert r.json() == {
        "message": "Invalid request.\n\n\"body\" wasn't supplied.",
        "documentation_url": "https://docs.github.com/rest/issues/comments#create-an-issue-comment",
        "status": "422",
    }
    r = session.post(pr.comments_url, json={"body": None})
    assert r.status_code == 422, r.text
    assert r.json() == {
        "message": "Invalid request.\n\nFor 'properties/body', nil is not a string.",
        "documentation_url": "https://docs.github.com/rest/issues/comments#create-an-issue-comment",
        "status": "422",
    }
    r = session.post(pr.comments_url, json={"body": ""})
    assert r.status_code == 422, r.text
    assert r.json() == {
        "message": "Validation Failed",
        "errors": [
            {
                "resource": "IssueComment",
                "code": "unprocessable",
                "field": "data",
                "message": "Body cannot be blank",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/issues/comments#create-an-issue-comment",
        "status": "422",
    }
    pr.create_issue_comment('a' * 262144)
    with pytest.raises(GithubException) as ghe:
        pr.create_issue_comment('a' * 262145)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "Validation Failed",
        "errors": [
            {
                "resource": "IssueComment",
                "code": "unprocessable",
                "field": "data",
                "message": "Body is too long (maximum is 65536 characters)",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/issues/comments#create-an-issue-comment",
        "status": "422",
    }
    pr.create_issue_comment('🌈' * 65536)
    with pytest.raises(GithubException) as ghe:
        pr.create_issue_comment('🌈' * 65536 + 'a')
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "Validation Failed",
        "errors": [
            {
                "resource": "IssueComment",
                "code": "unprocessable",
                "field": "data",
                "message": "Body is too long (maximum is 65536 characters)",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/issues/comments#create-an-issue-comment",
        "status": "422",
    }
