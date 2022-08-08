import pytest
import github as gh

from ... import check


def test_basic_flow():
    """Invite user, user rejects invitation, invite user again, they accept (?)

    Also try to invite the same user twice without changing permissions level,
    but that would probably be a no-op because it's basically changing the perms
    to what they already are?
    """


def test_invite_non_user(request, user, org):
    r = check(request, user.create_repo(__name__, auto_init=True))
    with pytest.raises(gh.GithubException) as ghe:
        r.add_to_collaborators("dummy-central-this-user-should-not-exist")
    assert ghe.value.status == 404
    assert ghe.value.data == {
        "status": '404',
        "message": "Not Found",
        "documentation_url": "https://docs.github.com/rest/collaborators/collaborators#add-a-repository-collaborator",
    }


def test_invite_self(request, user):
    r = check(request, user.create_repo(__name__, auto_init=True))
    with pytest.raises(gh.GithubException) as ghe:
        r.add_to_collaborators(user.login)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        "message": "Validation Failed",
        "errors": [
            {
                "resource": "Repository",
                "code": "custom",
                "message": "Repository owner cannot be a collaborator",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/reference/repos#add-a-repository-collaborator",
    }


def test_update_invite_permissions():
    """Update repo permissions of a user before they've accepted the invitation"""
    ...


def test_update_permission():
    """Update repo permissions of a user after they've accepted the invitation"""
