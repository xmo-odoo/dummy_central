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

class TestNonEmptyRepository:
    def xtest_update_branch_does_not_exist(self, repo):
        with pytest.raises(github.GithubException) as ghe:
            repo.create_file('test2', 'content', 'great', branch="bob")
        assert ghe.value.status == 404
        assert ghe.value.data == {
            "message": "Branch bob not found",
            "documentation_url": "https://docs.github.com/rest/repos/repos#create-or-update-file-contents"
        }
