import time

import pytest
import requests
from github import GithubException

from .. import make_branch


def wait(repo, cleanup=None):
    s = requests.Session()
    for t in [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]:
        time.sleep(t)
        if s.head(repo.url).ok:
            break
    else:
        raise Exception(f"Never saw repository {repo.url!r}")

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


def test_reviews(repo, users, endpoint, request, genbranch):
    url, get_hook = endpoint
    h = repo.create_hook(
        "web",
        {
            'url': url,
            'content_type': 'json',
        },
        ['pull_request_review'],
        active=True,
    )
    assert get_hook()[0] == 'ping'
    request.addfinalizer(h.delete)

    # can't review own PRs so create PR from a fork
    other = users('c')
    base = other.get_repo(repo.full_name)
    fork = wait(base.create_fork(), request.addfinalizer)
    branchname = genbranch()
    make_branch(fork, branchname)
    pr = base.create_pull(
        repo.default_branch, f"{fork.owner.login}:{branchname}", title="test"
    )

    # then switch back to main repo / user
    pr = repo.get_pull(pr.number)
    head = repo.get_commit(pr.head.sha)

    for review_type, comments, errors in [
        ('', [], 1),
        ('request_changes', [{}], 2),
        ('PENDING', [], 1),  # apparemment explicit pending is invalid
    ]:
        with pytest.raises(GithubException):
            pr.create_review(head, "xxx", review_type, comments)
        # # TODO: custom conversion failure?
        # assert e.value.status == 422
        # assert e.value.data['message'] == 'Unprocessable Entity'
        # # don't want to spec the errors messages because they're awful
        # assert len(e.value.data['errors']) == errors

    r = pr.create_review(
        head,
        "Ok :shrug:",
        'REQUEST_CHANGES',
        [
            {
                'path': 'foo',
                'position': 1,
                'body': "a comment",
            }
        ],
    )
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
