import pytest
from github import GithubException, InputGitTreeElement as item


def test_no_base(repo):
    t = repo.create_git_tree([item("foo", "100644", "blob", "whatever")])
    assert [e.path for e in t.tree] == ["foo"]


def test_missing_base(repo):
    base = repo.create_git_tree([item("foo", "100644", "blob", "whatever")])
    base._sha._value = "0" * 40

    with pytest.raises(GithubException) as ghe:
        repo.create_git_tree(
            [item("foo", "100644", "blob", "whatever2")],
            base_tree=base,
        )
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "base_tree is not a valid tree oid",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
        "status": "422",
    }


def test_invalid_base(repo):
    f = repo.create_git_blob("whatever", "utf-8")
    base = repo.create_git_tree([item("foo", "100644", "blob", sha=f.sha)])
    base._sha._value = f.sha

    with pytest.raises(GithubException) as ghe:
        repo.create_git_tree(
            [item("foo", "100644", "blob", "whatever2")],
            base_tree=base,
        )
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "base_tree is not a valid tree oid",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
        "status": "422",
    }


def test_nonhash_base(repo):
    base = repo.create_git_tree([item("foo", "100644", "blob", "whatever")])
    base._sha._value = "kljfdhsfahl"

    with pytest.raises(GithubException) as ghe:
        repo.create_git_tree(
            [item("foo", "100644", "blob", "whatever2")],
            base_tree=base,
        )
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "message": "base_tree is not a valid tree oid",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
        "status": "422",
    }


def test_invalid_path(repo):
    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("/foo", "100644", "blob", "")])

    assert e.value.status == 422
    assert e.value.data == {
        "status": '422',
        "message": "tree.path cannot start with a slash",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }


@pytest.mark.skip(reason="I don't wanna this is shit")
def test_mode(repo, session):
    t = repo.create_git_tree([item("foo", "100644", "tree", "")])
    assert t.tree[0].type == 'blob'

    b = repo.create_git_blob("", 'utf-8')
    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("bar", "040000", "blob", sha=b.sha)])
    assert e.value.status == 422
    assert e.value.data == {
        'status': '422',
        'message': 'GitRPC::BadObjectState',
        'documentation_url': 'https://docs.github.com/rest/git/trees#create-a-tree',
    }

    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("bar", "120000", "tree", sha=t.sha)])
    assert e.value.status == 422
    assert e.value.data == {
        "status": '422',
        "message": "GitRPC::BadObjectState",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }

    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("bar", "120000", "tree", sha=b.sha)])
    assert e.value.status == 422
    assert e.value.data == {
        "status": '422',
        "message": f"tree.sha {b.sha} is not a valid tree",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }

    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("foo", "100664", "tree", "")])
    assert e.value.status == 422
    assert e.value.data == {
        "status": '422',
        "message": "Must supply a valid tree.mode",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }

    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("foo", "15147", "tree", "")])
    e.value.status == 422
    assert e.value.data == {
        "status": '422',
        "message": "Must supply a valid tree.mode",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }

    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("foo", "15147", "blob", "")])
    assert e.value.data == {
        "status": '422',
        "message": "Must supply a valid tree.mode",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }

    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("bar", "040000", "blob", sha=t.sha)])
    assert e.value.status == 422
    assert e.value.data == {
        "status": '422',
        "message": f"tree.sha {t.sha} is not a valid blob",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }

    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("bar", "40000", "blob", "")])
    assert e.value.status == 422
    assert e.value.data == {
        "status": '422',
        "message": "Must supply a valid tree.mode",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }

    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("bar", "040000", "blob", "")])
    assert e.value.status == 422
    assert e.value.data == {
        "status": '422',
        "message": "A subdirectory may not have content",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }

    r = session.post(
        f"{repo.url}/git/trees",
        json={
            "tree": [
                {
                    "path": "bar",
                    "mode": "040000",
                    "type": "blob",
                    "content": None,
                }
            ],
        },
    )
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        "message": "Must supply either tree.sha or tree.content. Request will be rejected if both are present.",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }


@pytest.mark.skip(reason="needs better input validation support")
def test_no_content(repo):
    with pytest.raises(GithubException) as e:
        repo.create_git_tree([item("bar", "040000", "blob")])
    assert e.value.status == 422
    assert e.value.data == {
        "status": '422',
        "message": "Must supply either tree.sha or tree.content. Request will be rejected if both are present.",
        "documentation_url": "https://docs.github.com/rest/git/trees#create-a-tree",
    }
