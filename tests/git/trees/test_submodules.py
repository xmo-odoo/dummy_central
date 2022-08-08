import pytest
from github import GithubException, InputGitTreeElement as item


@pytest.mark.parametrize(
    'item',
    [
        pytest.param(
            lambda _: item("foo", "160000", "commit", sha="1" * 40),
            id="onesha",
        ),
        pytest.param(
            lambda r: item(
                "foo", "160000", "commit", sha=r.get_branch(r.default_branch).commit.sha
            ),
            id="ownhead",
        ),
    ],
)
def test_successes(repo, item):
    it = item(repo)
    t = repo.create_git_tree([it])

    assert [
        (e.path, e.mode, e.type, e.size, e.sha)
        for e in repo.get_git_tree(t.sha, recursive=True).tree
    ] == [('foo', '160000', 'commit', None, it._identity['sha'])]


@pytest.mark.parametrize(
    'item,err',
    [
        pytest.param(
            lambda _: item("foo", "160000", "commit", sha="0" * 40),
            "GitRPC::BadObjectState",
            id="nullsha",
        ),
        pytest.param(
            lambda _: item("foo", "160000", "commit", "0" * 40),
            "GitRPC::BadObjectState",
            id="nullcontent",
            marks=pytest.mark.xfail(
                reason="need to make model worse to validate post-deserialization"
            ),
        ),
        pytest.param(
            lambda _: item("foo", "160000", "commit", "0" * 40, sha='0' * 40),
            "Must supply either tree.sha or tree.content. Request will be rejected if both are present.",
            id="nullboth",
            marks=pytest.mark.xfail(
                reason="need to make model worse to validate post-deserialization"
            ),
        ),
        pytest.param(
            lambda _: item("foo", "160000", "commit", "1" * 40),
            "GitRPC::BadObjectState",
            id="onecontent",
            marks=pytest.mark.xfail(
                reason="need to make model worse to validate post-deserialization"
            ),
        ),
        pytest.param(
            lambda _: item("foo", "160000", "commit", "1" * 40, sha="1" * 40),
            "Must supply either tree.sha or tree.content. Request will be rejected if both are present.",
            id="oneboth",
            marks=pytest.mark.xfail(
                reason="need to make model worse to validate post-deserialization"
            ),
        ),
        pytest.param(
            lambda _: item("foo", "160000", "commit", sha='5'),
            "tree.sha 5 is not a valid commit",
            id="notsha",
        ),
        pytest.param(
            lambda _: item("foo", "160000", "commit", sha='x'),
            "tree.sha x is not a valid commit",
            id="notsha2",
        ),
    ],
)
def test_errors(repo, item, err):
    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item(repo)])

    assert e.value.status == 422
    assert e.value.data == {
        'status': '422',
        'documentation_url': "https://docs.github.com/rest/git/trees#create-a-tree",
        'message': err,
    }
