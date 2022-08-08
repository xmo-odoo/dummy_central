import github as gh
import pytest


def xtest_update_default_branch(repo):
    with pytest.raises(gh.GithubException) as ghe:
        repo.edit(default_branch=__name__)
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        "message": "Validation Failed",
        "errors": [
            {
                "message": "The branch bob was not found. Please push that ref first or create it via the Git Data API.",
                "resource": "Repository",
                "field": "default_branch",
                "code": "invalid",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/repos/repos#update-a-repository",
    }
