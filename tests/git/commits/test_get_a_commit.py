import pytest
from github import GithubException

def test_get_commit_wrong_type(request, repo):
    b = repo.create_git_blob("test", "utf-8")
    ref = repo.create_git_ref('refs/others/qiqiqi', b.sha)
    request.addfinalizer(ref.delete)

    with pytest.raises(GithubException) as ghe:
        repo.get_commit('refs/others/qiqiqi')
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "No commit found for SHA: refs/others/qiqiqi",
        "documentation_url": "https://docs.github.com/rest/commits/commits#get-a-commit"
    }
    with pytest.raises(GithubException) as ghe:
        repo.get_commit('others/qiqiqi')
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "No commit found for SHA: others/qiqiqi",
        "documentation_url": "https://docs.github.com/rest/commits/commits#get-a-commit"
    }

