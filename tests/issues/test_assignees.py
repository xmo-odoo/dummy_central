"""You can assign..."""

import pytest
from github import InputGitTreeElement as item

from .. import check


def test_yourself(repo, users):
    login = users('base').get_user().login
    issue = repo.create_issue("some issue")
    issue.add_to_assignees(login)
    issue.update()
    assert {u.login for u in issue.assignees} == {login}


def test_anyone_who_has_commented(repo, users):
    """You can add [...] anyone who has commented on the issue or pull request"""
    issue = repo.create_issue("some issue")
    login = users('c').get_user().login
    users('c').get_repo(repo.full_name).get_issue(issue.number).create_comment("hello")
    issue.add_to_assignees(login)
    issue.update()
    assert {u.login for u in issue.assignees} == {login}


def test_anyone_who_has_commented_includes_author(repo, users):
    """anyone who has commented on the issue or pull request extends
    to the author (which makes sense)
    """
    other_login = users('c').get_user().login
    r = users('c').get_repo(repo.full_name)
    issue = r.create_issue("some issue")
    i = repo.get_issue(issue.number)
    i.add_to_assignees(other_login)

    issue.update()
    assert {u.login for u in issue.assignees} == {other_login}
    assert {u.login for u in i.assignees} == {other_login}


@pytest.mark.skip("collaborator is todo (?)")
def test_anyone_with_write_permission():
    pass


@pytest.mark.skip("org membership is todo (??)")
def test_organization_members_with_read_permission():
    pass


@pytest.mark.skip("TODO")
def test_assignees_limit():
    pass


def test_not_contributor(request, repo, users):
    """A past contributor or current interactor (in a different
    thread) is not assignable
    """
    repo.get_git_ref(f'heads/{repo.default_branch}').edit(
        (
            c := repo.create_git_commit(
                'base',
                tree=repo.create_git_tree([item('kldsfjh', '100644', 'blob', '')]),
                parents=[],
            )
        ).sha,
        force=True,
    )

    c_user = users('c')
    c_repo = c_user.get_repo(repo.full_name)
    fork = check(request, (c_repo.create_fork()))
    t = fork.create_git_tree([item('xxx', '100644', 'blob', 'blorp')])
    c = fork.create_git_commit('thing', tree=t, parents=[c])
    # So apparently commits don't become shared as soon as they're
    # created? This seems extremely surprising, apparently github's
    # network system is a lot more complicated than believed...
    fork.create_git_ref('refs/heads/sdkfjha', c.sha)
    c_login = c_user.get_user().login
    c_repo.create_pull(
        repo.default_branch,
        f'{c_login}:sdkfjha',
        title='sk8er loser',
    )

    r = repo.get_git_ref(f'heads/{repo.default_branch}')
    r.edit(c.sha)

    assert c_user.get_user(c_login) in repo.get_contributors()
    issue = repo.create_issue("some issue")
    login = users('c').get_user().login
    issue.add_to_assignees(login)
    issue.update()
    assert {u.login for u in issue.assignees} == set()


def test_not_rando(repo, users):
    """An entirely unaffiliated user is not assignable"""
    issue = repo.create_issue("some issue")
    login = users('c').get_user().login
    issue.add_to_assignees(login)
    issue.update()
    assert {u.login for u in issue.assignees} == set()
