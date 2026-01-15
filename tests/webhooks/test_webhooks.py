"""
This module tests the manipulation of webhook objects
"""

import time
import pytest
from github import GithubException


def test_repo_hook_mismatch(request, org, repo, create_repo, session):
    """Even though webhook ids are global, a hook can only be found within
    its owner repo.
    """
    h = repo.create_hook(
        "web",
        {
            'url': "https://example.org",
            'content_type': 'json',
        },
        ['pull_request_review'],
        active=True,
    )
    request.addfinalizer(h.delete)

    r2 = create_repo()

    # can't do this with pygithub as it keeps full links
    r = session.patch(
        f"{r2.url}/hooks/{h.id}",
        json={"active": True},
    )
    assert r.status_code == 404, r.text
    assert r.json() == {
        "message": "Not Found",
        "documentation_url": "https://docs.github.com/rest/repos/webhooks#update-a-repository-webhook",
        "status": "404",
    }

    r = session.delete(f"{r2.url}/hooks/{h.id}")
    assert r.status_code == 404, r.text
    assert r.json() == {
        "message": "Not Found",
        "documentation_url": "https://docs.github.com/rest/repos/webhooks#delete-a-repository-webhook",
        "status": "404",
    }


def test_hook_create(request, repo, session):
    h = repo.create_hook('web', {'url': 'https://example.org'})
    request.addfinalizer(h.delete)
    assert h.type == "Repository"
    assert h.name == 'web'
    assert h.events == ['push']
    assert h.active is True
    assert h.url == f'{repo.url}/hooks/{h.id}'
    assert h.test_url == f'{repo.url}/hooks/{h.id}/test'
    assert h.ping_url == f'{repo.url}/hooks/{h.id}/pings'
    assert h.deliveries_url == f'{repo.url}/hooks/{h.id}/deliveries'
    assert h.config == {
        'url': 'https://example.org',
        'content_type': 'form',
        'insecure_ssl': '0',
    }
    assert h.last_response.code is None
    assert h.last_response.status == "unused"
    assert h.last_response.message is None

    for t in range(1, 11):
        time.sleep(t)
        h.update()
        if h.last_response.code is not None:
            break
    else:
        pytest.fail("initial ping delivery never resolved")
    assert h.last_response.code in (
        403,
        405,
        502,
    )  # sometimes example.org refuses to respond
    assert h.last_response.status is None

    h = repo.create_hook('web', {'url': 'https://example.org/2'}, [])
    request.addfinalizer(h.delete)
    assert h.events == ['push']

    with pytest.raises(GithubException) as e:
        repo.create_hook('web', {'url': 'https://example.org'})
    assert e.value.status == 422
    assert e.value.data == {
        "message": "Validation Failed",
        "errors": [
            {
                "code": "custom",
                "resource": "Hook",
                "message": "Hook already exists on this repository",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/repos/webhooks#create-a-repository-webhook",
        "status": "422",
    }

    with pytest.raises(GithubException) as e:
        repo.create_hook('xxx', {'url': 'https://example.org'})
    assert e.value.status == 422
    e.value.data['errors'][0].pop('value', None)
    assert e.value.data == {
        "message": "Validation Failed",
        "errors": [
            {
                # "value": "xxx",
                "resource": "Hook",
                "field": "name",
                "code": "invalid",
            }
        ],
        "documentation_url": "https://docs.github.com/rest/repos/webhooks#create-a-repository-webhook",
        "status": "422",
    }
    with pytest.raises(GithubException) as e:
        repo.create_hook('web', {})
    assert e.value.status == 422
    assert e.value.data == {
        "message": "Validation Failed",
        "errors": [
            {
                'code': 'custom',
                'field': 'url',
                'message': 'url cannot be blank',
                'resource': 'Hook',
            }
        ],
        "documentation_url": "https://docs.github.com/rest/repos/webhooks#create-a-repository-webhook",
        "status": "422",
    }

    # TODO: custom error serialization in serde?
    # with pytest.raises(GithubException) as e:
    #     repo.create_hook('web', {'url': 'https://example.org'}, ['xxx'])
    # assert e.value.status == 422
    # assert e.value.data == {
    #     "message": "Validation Failed",
    #     "errors": [{
    #         'code': 'custom',
    #         'message': 'xxx is not a valid event name',
    #         'resource': 'Hook',
    #     }],
    #     "documentation_url": "https://docs.github.com/rest/repos/webhooks#create-a-repository-webhook",
    #     "status": "422",
    # }

    # what in the fuck? Yeah I'm not doing that, sorry, fuck you.
    # r = repo.create_hook("web", {'url': 'https://example.org/42', 'insecure_ssl': ['cowabunga']})
    # request.addfinalizer(h.delete)
    # assert r.config['insecure_ssl'] == ['cowabunga']
    # assert repo.get_hook(r.id).config['insecure_ssl'] == ['cowabunga']


def test_hook_update(request, repo, session):
    h = repo.create_hook(
        "web",
        {
            'url': 'https://example.org',
            'content_type': 'json',
            'insecure_ssl': True,
        },
        ['pull_request_review'],
        active=True,
    )
    request.addfinalizer(h.delete)
    assert h.events == ['pull_request_review']
    assert h.config == {
        'url': 'https://example.org',
        'content_type': 'json',
        'insecure_ssl': '1',
    }

    h.edit('bob', {})
    assert h.name == 'web'
    h.edit(
        'web',
        {},
        events=['push'],
        add_events=['status'],
        remove_events=['push'],
        active=False,
    )
    assert h.events == ['push']
    assert h.active is False
    assert h.config == {
        'url': 'https://example.org',
        'content_type': 'json',
        'insecure_ssl': '1',
    }
    h.edit('web', {})
    assert h.events == ['push']
    assert h.active is False
    h.edit('web', {}, events=[])
    assert h.events == ["push"]
    h.edit('web', {}, remove_events=["status"])
    assert h.events == ["push"]
    h.edit('web', {}, add_events=["status"], remove_events=["status"])
    assert h.events == ["push", 'status']
    h.edit('web', {}, add_events=["status"], remove_events=["status"])
    assert h.events == ["push", 'status']
    h.edit('web', {}, remove_events=["push", "status"])
    assert h.events == []
