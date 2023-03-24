import pytest
from github import GithubException

MISSING_OID = 'eeed0456ca0e8d129a91bd4826732ab95a3edbb6'

def test_invalid_refs(repo):

    with pytest.raises(GithubException) as ghe:
        repo.create_git_ref('refs/heads/missing', MISSING_OID)
    assert ghe.value.status == 422
    assert ghe.value.data  == {
        'message': 'Object does not exist',
        'documentation_url': 'https://docs.github.com/rest/reference/git#create-a-reference'
    }

    b = repo.create_git_blob("test", "utf-8")
    with pytest.raises(GithubException) as ghe:
        repo.create_git_ref('refs/heads/nonsense', b.sha)
    assert ghe.value.status == 422, "refs/heads are branches and can only point towards commits"
    assert ghe.value.data == {
        "message": "Reference update failed",
        "documentation_url": "https://docs.github.com/rest/reference/git#create-a-reference"
    }

    with pytest.raises(GithubException) as ghe:
        repo.create_git_ref('refs/nonsense', b.sha)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/git#create-a-reference',
        'message': "Reference name must contain at least three slash-separated components."
    }
    with pytest.raises(GithubException) as ghe:
        repo.create_git_ref('others/nonsense', b.sha)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/git#create-a-reference',
        'message': "Reference name must start with 'refs/'."
    }

    ref = repo.create_git_ref('refs/others/nonsense', b.sha)
    assert ref.object.type == 'blob'
    assert ref.object.sha == b.sha

    with pytest.raises(GithubException) as ghe:
        repo.create_git_ref('refs/others/nonsense', b.sha)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/git#create-a-reference',
        'message': 'Reference already exists'
    }

    o = repo.get_git_ref('others/nonsense').object
    assert o.type == 'blob'
    assert o.sha == b.sha

    c = repo.create_git_blob("test2", "utf-8")
    ref.edit(c.sha)
    assert repo.get_git_ref('others/nonsense').object.sha == c.sha

    assert [r.ref for r in repo.get_git_refs()] == [f'refs/heads/{repo.default_branch}', 'refs/others/nonsense']

    ref.delete()
    with pytest.raises(GithubException) as ghe:
        ref.delete()
    assert ghe.value.status == 422
    assert ghe.value.data == {
        'documentation_url': 'https://docs.github.com/rest/reference/git#delete-a-reference',
         'message': 'Reference does not exist'
    }
