import pytest
from github import GithubException


def test_get_refs(repo, endpoint, session):
    init = repo.get_commit('refs/heads/' + repo.default_branch).commit
    url, get_hook = endpoint
    repo.create_hook(
        "web",
        {
            'url': url,
            'content_type': 'json',
        },
        ["status"],
        active=True,
    )
    assert get_hook()[0] == 'ping'

    # nb: get_git_ref is on `ref/` not `refs/`, but both work (and the latter is canonical)
    ref = repo.get_git_ref(f'heads/{repo.default_branch}')
    blob = repo.create_git_blob("blobish volleysh", "utf-8")
    main = repo.get_commit(f'heads/{repo.default_branch}')
    assert ref.ref == f'refs/heads/{repo.default_branch}'
    assert ref.url.endswith(f'git/refs/heads/{repo.default_branch}')
    assert ref.object.sha == init.sha
    assert main.sha == init.sha
    assert repo.get_commit(f'refs/heads/{repo.default_branch}').sha == init.sha

    with pytest.raises(GithubException) as ghe:
        repo.get_git_ref('heads/main2')
    assert ghe.value.status == 404
    assert ghe.value.data == {
        'status': '404',
        'documentation_url': 'https://docs.github.com/rest/git/refs#get-all-references-in-a-namespace',
        'message': 'Not Found',
    }

    main.create_status(
        state="pending",
        target_url="https://example.org/test",
        description="This is my ci",
        context="ci",
    )
    event, payload = get_hook()
    assert event == 'status'
    assert payload['sha'] == main.sha
    assert payload['context'] == 'ci'
    assert payload['state'] == 'pending'
    assert payload['target_url'] == 'https://example.org/test'
    assert payload['description'] == 'This is my ci'

    main.create_status(state="success")
    event, payload = get_hook()
    assert event == 'status'
    assert payload['sha'] == main.sha
    assert payload['context'] == 'default'
    assert payload['state'] == 'success'
    assert payload['target_url'] is None
    assert payload['description'] is None

    with pytest.raises(GithubException) as ghe:
        main.create_status(state="invalid")
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        "message": "Validation Failed",
        "errors": 'Validation failed: State is not included in the list',
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status",
    }
    with pytest.raises(GithubException) as ghe:
        main.create_status(state='success', context='')
    assert ghe.value.status == 422
    assert ghe.value.data == {
        "status": '422',
        "message": "Validation Failed",
        "errors": "Validation failed: Context can't be blank",
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status",
    }

    # create_status requires a status so use raw json
    r = session.post(repo.statuses_url.format(sha=main.sha), json={})
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        "message": "Validation Failed",
        "errors": 'Validation failed: State is not included in the list',
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status",
    }

    # create_status works off of a real commit object so...
    NULL = "0" * 40
    r = session.post(repo.statuses_url.format(sha=NULL), json={})
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        "message": f"No commit found for SHA: {NULL}",
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status",
    }

    r = session.post(repo.statuses_url.format(sha="this is not a valid sha"), json={})
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        "message": "No commit found for SHA: this is not a valid sha",
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status",
    }

    r = session.post(repo.statuses_url.format(sha=blob.sha), json={})
    assert r.status_code == 422
    assert r.json() == {
        "status": '422',
        "message": f"No commit found for SHA: {blob.sha}",
        "documentation_url": "https://docs.github.com/rest/commits/statuses#create-a-commit-status",
    }
