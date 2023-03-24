
import pytest
from github import GithubException, InputGitTreeElement as item

MISSING_OID = 'eeed0456ca0e8d129a91bd4826732ab95a3edbb6'

def ident(user):
    """Identifier data for AuthenticatedUser and NamedUser
    """
    return user.login, user.email, user.name, user.type

def test_update_ref(request, repo, user):
    init = repo.create_file("foo", "bar", "baz")['commit']
    init = repo.get_git_commit(init.sha)

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

    # create a ref which doesn't exist: fetch existing ref then update its
    # identity attributes to change the refname (and url) to something which
    # does not
    ref2 = repo.get_git_ref('heads/other')
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