import secrets
import github
import pytest

"""
TODO: edge cases and errors of the content API

- path is empty
- don't pass in a `sha` when updating a file
- do pass in a sha when creating a file
- can a full ref be given?
- where are branches checked for not mapping to a non-commit?
- how are nonsensical paths handled e.g. foo//bar?
"""


class TestEmptyRepository:
    """The contents API is a special kind of mess when called on an empty
    repository:

    - it can be used with a branch which does not exist (which is not normally the case)
    - it may or may not update the default branch
    - it's the only call affecting git contents which can be performed on an
      empty repository, the git database calls don't work
    """


# @pytest.mark.skip("TODO: implement")
class TestNonEmptyRepository:
    def test_new_branch(self, repo):
        branch_name = secrets.token_hex(8)
        with pytest.raises(github.GithubException) as ghe:
            repo.create_file('test2', 'content', 'great', branch=branch_name)
        assert ghe.value.status == 404
        assert ghe.value.data == {
            "status": "404",
            "message": f"Branch {branch_name} not found",
            "documentation_url": "https://docs.github.com/rest/repos/contents#create-or-update-file-contents",
        }

    def test_empty_branch(self, repo):
        with pytest.raises(github.GithubException) as ghe:
            repo.create_file('test2', 'content', 'great', branch="")
        assert ghe.value.status == 404
        assert ghe.value.data == {
            "status": "404",
            "message": "Branch  not found",
            "documentation_url": "https://docs.github.com/rest/repos/contents#create-or-update-file-contents",
        }
