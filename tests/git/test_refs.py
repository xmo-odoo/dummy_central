import copy

import pytest
import requests
from github import GithubException, InputGitTreeElement as item

MISSING_OID = 'eeed0456ca0e8d129a91bd4826732ab95a3edbb6'

def ident(user):
    """Identifier data for AuthenticatedUser and NamedUser
    """
    return user.login, user.email, user.name, user.type

def test_get_refs(repo, endpoint, config):
    init = repo.get_commit('refs/heads/' + repo.default_branch).commit
    url, get_hook = endpoint
    repo.create_hook("web", {
        'url': url,
        'content_type': 'json',
    }, ["status"], active=True)
    assert get_hook()[0] == 'ping'

    # nb: get_git_ref is on `ref/` not `refs/`, but both work (and the latter is canonical)
    ref = repo.get_git_ref(f'heads/{repo.default_branch}')
    blob = repo.create_git_blob("blobish volleysh", "utf-8")
    main = repo.get_commit(f'heads/{repo.default_branch}')
    assert ref.ref == f'refs/heads/{repo.default_branch}'
    assert ref.url.endswith(f'git/refs/heads/{repo.default_branch}')
    assert ref.object.sha == init.sha
    assert main.sha == init.sha
    assert repo.get_commit(f'refs/heads/{repo.default_branch}').sha == init.sha

    with pytest.raises(GithubException) as ghe:
        repo.get_git_ref('heads/main2')
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/git#get-a-reference',
        'message': 'Not Found'
    }

    main.create_status(
        state="pending",
        target_url="https://example.org/test",
        description="This is my ci",
        context="ci"
    )
    event, payload = get_hook()
    assert event == 'status'
    assert payload['sha'] == main.sha
    assert payload['context'] == 'ci'
    assert payload['state'] == 'pending'
    assert payload['target_url'] == 'https://example.org/test'
    assert payload['description'] == 'This is my ci'

    main.create_status(state="success")
    event, payload = get_hook()
    assert event == 'status'
    assert payload['sha'] == main.sha
    assert payload['context'] == 'default'
    assert payload['state'] == 'success'
    assert payload['target_url'] is None
    assert payload['description'] is None

    with pytest.raises(GithubException) as ghe:
        main.create_status(state="invalid")
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "Validation Failed",
        "errors": [{
            "resource": "Status",
            "code": "custom",
            "field": "state",
            "message": "state is not included in the list"
        }],
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status"
    }
    with pytest.raises(GithubException) as ghe:
        main.create_status(state='success', context='')
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "Validation Failed",
        "errors": [{
            "resource": "Status",
            "code": "missing_field",
            "field": "context"
        }],
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status"
    }

    # create_status requires a status so use raw json
    r = requests.post(
        repo.statuses_url.format(sha=main.sha),
        headers={'Authorization': f'token {config["token"]}' },
        json={}
    )
    assert r.status_code == 422
    assert r.json() == {
        "message": "Validation Failed",
        "errors": [{
            "resource": "Status",
            "code": "custom",
            "field": "state",
            "message": "state is not included in the list"
        }],
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status"
    }

    # create_status works off of a real commit object so...
    NULL = "0"*40
    r = requests.post(
        repo.statuses_url.format(sha=NULL),
        headers={'Authorization': f'token {config["token"]}' },
        json={}
    )
    assert r.status_code == 422
    assert r.json() == {
        "message": f"No commit found for SHA: {NULL}",
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status"
    }

    r = requests.post(
        repo.statuses_url.format(sha="this is not a valid sha"),
        headers={'Authorization': f'token {config["token"]}' },
        json={}
    )
    assert r.status_code == 422
    assert r.json() == {
        "message": "No commit found for SHA: this is not a valid sha",
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status"
    }

    r = requests.post(
        repo.statuses_url.format(sha=blob.sha),
        headers={'Authorization': f'token {config["token"]}' },
        json={}
    )
    assert r.status_code == 422
    assert r.json() == {
        "message": f"No commit found for SHA: {blob.sha}",
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status"
    }

def test_update_ref(request, repo, user):
    init = repo.get_commit('refs/heads/' + repo.default_branch).commit

    c0 = repo.create_git_commit(
        message="msg",
        tree=repo.create_git_tree([
            item('foo', '100644', 'blob', 'ok')
        ]),
        parents=[init]
    )
    ref = repo.create_git_ref('refs/heads/other', c0.sha)
    request.addfinalizer(ref.delete)
    # see what happens if we update a ref to itself
    ref.edit(c0.sha)

    with pytest.raises(GithubException) as ghe:
        ref.edit(c0.tree.sha)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'message': 'Object is not a commit',
        'documentation_url': 'https://docs.github.com/rest/reference/git#update-a-reference',
    }

    with pytest.raises(GithubException) as ghe:
        ref.edit(MISSING_OID)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'message': 'Object does not exist',
        'documentation_url': 'https://docs.github.com/rest/reference/git#update-a-reference',
    }

    descendant = repo.create_git_commit(
        message="descendant",
        tree=repo.create_git_tree([
            item('bar', '100644', 'blob', 'ok')
        ], c0.tree),
        parents=[c0]
    )
    ref.edit(descendant.sha)

    sibling = repo.create_git_commit(
        message="sibling",
        tree=repo.create_git_tree([
            item('baz', '100644', 'blob', 'yay')
        ]),
        parents=[init]
    )
    with pytest.raises(GithubException) as ghe:
        ref.edit(sibling.sha)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/git#update-a-reference',
        'message': 'Update is not a fast forward'
    }
    ref.edit(sibling.sha, force=True)

    # create a ref which doesn't exist
    ref2 = copy.deepcopy(ref)
    # update attributes to change the refname to something which
    # doesn't exist, object does not change
    ref2._ref.value += '2'
    ref2._url.value += '2'

    with pytest.raises(GithubException) as ghe:
        ref2.edit(sibling.sha)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'message': 'Reference does not exist',
        'documentation_url': 'https://docs.github.com/rest/reference/git#update-a-reference',
    }

    with pytest.raises(GithubException) as ghe:
        ref2.delete()
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'message': 'Reference does not exist',
        'documentation_url': 'https://docs.github.com/rest/reference/git#delete-a-reference',
    }

    # TODO: what happens if we update a non-heads commit ref to a non-descendant?
    # TODO: what happens if we update a non-heads commit ref to a non-commit?
    # TODO: update-ref without a slash (not achievable with pygithub, unless we create a ref object by hand)

    # check that the caller of the API is the author and committer of commits
    # created directly or via the contents API
    assert init.author.name == init.committer.name \
        == c0.author.name == c0.committer.name \
        == user.login
    assert init.author.email == init.committer.email \
        == c0.author.email == c0.committer.email \
        == user.email or 'user@example.org'

    m = repo.merge(repo.default_branch, "other")
    default_ref = repo.get_git_ref(f"heads/{repo.default_branch}")
    assert default_ref.object.sha == m.sha, "/merges should update the base branch"
    assert [p.sha for p in m.parents] == [init.sha, ref.object.sha]
    assert m.commit.message == "Merge other into %s" % repo.default_branch
    assert m.commit.author.date == m.commit.committer.date, \
        "checks that the time-of-commit is coherent"

    # the author is the API caller
    assert ident(m.author) == ident(user)
    assert m.commit.author.name == user.login

    # and now shit gets weird: the committer for the /merges API is *not* the 
    # caller, it's a synthetic user
    assert ident(m.committer) == ("web-flow", None, "GitHub Web Flow", "User")
    assert m.commit.committer.name == "GitHub"
    assert m.commit.committer.email == "noreply@github.com"

    default_ref.edit(init.sha, force=True)
    m2 = repo.merge(repo.default_branch, ref.object.sha)
    assert repo.get_git_ref(f"heads/{repo.default_branch}").object.sha == m2.sha
    assert [p.sha for p in m2.commit.parents] == [init.sha, ref.object.sha]
    assert m2.commit.message == "Merge %s into %s" % (ref.object.sha, repo.default_branch)