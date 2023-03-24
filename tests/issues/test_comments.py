
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


def test_issue_comments(repo, pr, endpoint, request):
    url, get_hook = endpoint
    h = repo.create_hook("web", {
        'url': url,
        'content_type': 'json',
    }, ['issue_comment'], active=True)
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
        'documentation_url': 'https://docs.github.com/rest/reference/issues#get-an-issue-comment',
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
        "well that looks odd"
    ]
    c.delete()
    issue, comment = event('deleted', get_hook())
    assert issue['number'] == pr.number
    assert comment['body'] ==  "this is absolute genius!"

    assert [c.body for c in pr.get_issue_comments()] == ["well that looks odd"]
    # HA HA
    with pytest.raises(GithubException) as ghe:
        c.edit("whoopsie")
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/issues#update-an-issue-comment',
        'message': 'Not Found',
    }
    with pytest.raises(GithubException) as ghe:
        c.delete()
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/issues#delete-an-issue-comment',
        'message': 'Not Found',
    }



