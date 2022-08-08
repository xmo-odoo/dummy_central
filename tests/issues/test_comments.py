import time

import pytest
import requests
from github import Github, InputGitTreeElement as item, GithubException

def wait(repo, cleanup=None):
    s = requests.Session()
    for t in [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]:
        time.sleep(t)
        if s.head(repo.url).ok:
            break
    else:
        raise Exception(f"Never saw repository {r.url!r}")

    if cleanup:
        @cleanup
        def _cleanup():
            try:
                repo.delete()
            except GithubException as e:
                if e.status == 404:
                    return
                raise
    return repo

# The PGH API has has "issue comments" for regular comments
# (`PullRequest.create_issue_comment`) and "comments" or "review
# comments" for... review comments.
#
# Seems like straight "review comments" are about immediately
# submitted inline comments, for comments associated with an actual
# review, the comment contents probably need to be passed to
# `create_review` instead.

def event(action, e):
    event, payload = e
    assert event == 'issue_comment'
    assert payload['action'] == action
    if action != 'edited':
        return payload['issue'], payload['comment']
    else:
        return payload['issue'], payload['comment'], payload['changes']

def make_branch(repo, name):
    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit

    t = repo.create_git_tree([
        item('foo', '100644', 'blob', 'blorp'),
    ], base_tree=d_head.tree)
    c = repo.create_git_commit("a commit", t, [d_head])
    return repo.create_git_ref(f'refs/heads/{name}', c.sha)

@pytest.fixture(scope='module') # have every thing work off of the same pr
def pr(repo, config):
    ref = make_branch(repo, __name__)
    yield repo.create_pull("test", "", base=repo.default_branch, head=__name__)
    ref.delete()


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

def test_review_comments(repo, pr):
    head = repo.get_commit(pr.head.sha)
    c = pr.create_review_comment('what', head, 'foo', 1)
    assert pr.get_review_comment(c.id).body == 'what'
    c.edit('xxx')
    pr.create_review_comment('wheee', head, 'foo', 1)
    assert [c.body for c in pr.get_review_comments()] == [
        'xxx',
        'wheee'
    ]
    c.delete()
    assert [c.body for c in pr.get_review_comments()] == ['wheee']


def test_reviews(repo, users, endpoint, request):
    url, get_hook = endpoint
    h = repo.create_hook("web", {
        'url': url,
        'content_type': 'json',
    }, ['pull_request_review'], active=True)
    assert get_hook()[0] == 'ping'
    request.addfinalizer(h.delete)

    # can't review own PRs so create PR from a fork
    other = users('c')
    base = other.get_repo(repo.full_name)
    fork = wait(base.create_fork(), request.addfinalizer)
    make_branch(fork, 'create_pr2')
    pr = base.create_pull("test", "", base=repo.default_branch, head=f"{fork.owner.login}:create_pr2")

    # then switch back to main repo / user
    pr = repo.get_pull(pr.number)
    head = repo.get_commit(pr.head.sha)

    for review_type, comments, errors in [
            ('', [], 1),
            ('request_changes', [{}], 2),
            ('PENDING', [], 1), # apparemment explicit pending is invalid
    ]:
        with pytest.raises(GithubException) as e:
            pr.create_review(head, "xxx", review_type, comments)
        # # TODO: custom conversion failure?
        # assert e.value.status == 422
        # assert e.value.data['message'] == 'Unprocessable Entity'
        # # don't want to spec the errors messages because they're awful
        # assert len(e.value.data['errors']) == errors

    r = pr.create_review(head, "Ok :shrug:", 'REQUEST_CHANGES', [{
        'path': 'foo',
        'position': 1,
        'body': "a comment",
    }])
    assert r.state == 'CHANGES_REQUESTED'

    event, payload = get_hook()
    assert event == 'pull_request_review'
    assert payload['action'] == 'submitted'
    assert payload['pull_request']['number'] == pr.number
    assert payload['review']['state'] == 'changes_requested'
    assert payload['review']['body'] == 'Ok :shrug:'

    assert [r.body for r in pr.get_reviews()] == ['Ok :shrug:']
    assert [c.body for c in pr.get_single_review_comments(r.id)] == ['a comment']

    r = pr.create_review(head, "Ok :shrug:", 'APPROVE')
    assert r.state == 'APPROVED'
    event, payload = get_hook()
    assert event == 'pull_request_review'
    assert payload['action'] == 'submitted'
    assert payload['pull_request']['number'] == pr.number
    assert payload['review']['state'] == 'approved'
    assert payload['review']['body'] == 'Ok :shrug:'

    r = pr.create_review(head, "Ok :shrug:", 'COMMENT')
    assert r.state == 'COMMENTED'
    event, payload = get_hook()
    assert event == 'pull_request_review'
    assert payload['action'] == 'submitted'
    assert payload['pull_request']['number'] == pr.number
    assert payload['review']['state'] == 'commented'
    assert payload['review']['body'] == 'Ok :shrug:'
