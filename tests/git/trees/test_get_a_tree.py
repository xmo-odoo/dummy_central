import base64

from github import InputGitTreeElement as item
import pytest


@pytest.fixture
def t(repo):
    return repo.create_git_tree(
        [
            item("foo/bar/baz", "100644", "blob", "whatever"),
        ]
    )


def test_get(repo, t):
    t = repo.get_git_tree(t.sha, recursive=False)
    assert len(t.tree) == 1
    assert t.tree[0].path == "foo"


def test_recursive(repo, session, t):
    tt = repo.get_git_tree(t.sha, recursive=True)
    assert len(tt.tree) == 3
    assert [(ttt.path, ttt.type) for ttt in tt.tree] == [
        ("foo", "tree"),
        ("foo/bar", "tree"),
        ("foo/bar/baz", "blob"),
    ]
    c = base64.b64decode(repo.get_git_blob(tt.tree[2].sha).content)
    assert c == b'whatever'


@pytest.mark.parametrize(
    "param,count",
    [
        ("", 1),
        ("=", 3),
        ("=0", 3),
        ("=false", 3),
        ("=chicken", 3),
    ],
)
def test_recursive_values(repo, session, t, param, count):
    # pygithub coerces recursive=non_falsy to recursive=1, according to the doc
    # > Setting this parameter to any value
    # triggers recursive fetching, only ommitting it doesn't
    # can't use an empty list because urlencode(doseq) causes it to get splatted
    for v in ["0", "false", "chicken", ""]:
        r = session.get(f"{repo.url}/git/trees/{t.sha}", params={"recursive": v})
        assert r.ok, r.text
        assert len(r.json()['tree']) == 3, r.text

    r = session.get(f"{repo.url}/git/trees/{t.sha}", params=f"recursive{param}")
    assert r.ok, r.text
    assert len(r.json()['tree']) == count, r.text
