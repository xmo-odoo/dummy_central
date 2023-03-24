from github import InputGitTreeElement as item

from ... import pr_payload

def set_file(repo, ref, *, message, name, content):
    assert ref.object.type == 'commit'
    previous = repo.get_git_commit(ref.object.sha)
    t = repo.create_git_tree([
        item(name, '100644', 'blob', content)
    ], base_tree=previous.tree)
    c = repo.create_git_commit(message, t, [previous])
    ref.edit(c.sha)
    return c

def test_synchronize(repo, config, endpoint, request):
    url, get_hook = endpoint
    h = repo.create_hook("web", {
        'url': url,
        'content_type': 'json',
    }, ['pull_request'], active=True)
    assert get_hook()[0] == 'ping'
    request.addfinalizer(h.delete)

    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    pr_branch = repo.create_git_ref('refs/heads/pr', d.commit.sha)
    set_file(repo, pr_branch, message="a commit", name='foo', content='blorp')

    pr = repo.create_pull("test", "", base=repo.default_branch, head="pr")
    payload = pr_payload(get_hook())
    assert payload['action'] == 'opened'
    update = set_file(repo, pr_branch, message='an other', name='foo', content='blorp again')
    payload = pr_payload(get_hook())
    assert payload['action'] == 'synchronize'
    assert payload['number'] == pr.number
    # webhook has undocumented "before" and "after" keys, which could
    # be useful but... (also not `changes` for some reason)
    assert payload.keys() > {'action', 'number', 'pull_request', 'repository'}
    head = payload['pull_request']['head']
    assert head['ref'] == 'pr'
    assert head['label'] == f'{repo.owner.login}:pr'
    assert head['sha'] == update.sha