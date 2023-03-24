
def test_empty(repo):
    init = repo.get_commit(f'refs/heads/{repo.default_branch}').commit
    desc = repo.create_git_commit(
        message="test empty",
        tree=init.tree,
        parents=[init]
    )

    assert desc.tree == init.tree