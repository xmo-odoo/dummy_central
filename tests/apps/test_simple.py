import secrets
import subprocess
import time
from collections.abc import Generator
from urllib.parse import urlsplit
import webbrowser

import pytest
import requests
from github.GithubException import GithubException

import github

from .. import check


@pytest.fixture(scope='module')
def base_url(pytestconfig) -> Generator[str]:
    yield pytestconfig.getoption('--base-url')


@pytest.fixture(scope='module')
def repo(request, app, org, base_url):
    _installation = app.install(org)
    request.addfinalizer(lambda: app.uninstall(org))

    inst = github.Github(
        base_url=base_url,
        auth=app.iat(org, {'administration': 'write'}),
    )
    yield check(
        request,
        inst.get_organization(org.login).create_repo(
            secrets.token_hex(8),
            auto_init=True,
            # necessary to trigger ACL checks on issues creation
            private=True,
        ),
    )


def test_content_access(repo, app, org, base_url):
    inst = github.Github(base_url=base_url, auth=app.iat(org, {'contents': 'write'}))
    r = inst.get_organization(org.login).get_repo(repo.name)
    ref = r.get_git_ref('heads/' + r.default_branch)
    commit = r.create_file("foo", "a message", "some content")['commit']
    assert ref.object.sha != commit.sha
    original = ref.object.sha
    ref.update()
    assert ref.object.sha == commit.sha
    with pytest.raises(GithubException) as e:
        ref.edit(sha=original)
    assert e.value.data == {
        'documentation_url': 'https://docs.github.com/rest/git/refs#update-a-reference',
        'message': 'Update is not a fast forward',
        'status': '422',
    }
    ref.edit(sha=original, force=True)
    ref2 = r.create_git_ref('refs/heads/other', commit.sha)
    ref2.delete()

    r.get_git_commit(commit.sha)


def test_issues_manipulations(repo, app, org, base_url):
    inst = github.Github(base_url=base_url, auth=app.iat(org, {'issues': 'write'}))
    issues_w = inst.get_organization(org.login).get_repo(repo.name)

    issue = issues_w.create_issue('an issue')
    issue.update()
    c = issue.create_comment("a comment")
    for c in issue.get_comments():
        pass
    issue.add_to_labels("foo", "bar")
    c.create_reaction('heart')
    issue.edit(state='closed', state_reason='duplicate')

    # pr:w allows accessing issue endpoints *for prs* (which makes sense but is
    # not obvious from the docs), so to create a PR from an issue I guess the
    # IAT needs i:r, pr:w (which makes sense)
    # FIXME: uncomment when perms (per iat) are implemented
    # inst = github.Github(base_url=base_url, auth=app.iat(org, {'pull_requests': 'write'}))
    # prs_w = inst.get_organization(org.login).get_repo(repo.name)
    # with pytest.raises(GithubException) as e:
    #     issue = prs_w.get_issue(issue.number)
    # assert e.value.data == {
    #     "status": "403",
    #     "message": "Resource not accessible by integration",
    #     "documentation_url": "https://docs.github.com/rest/issues/issues#get-an-issue",
    # }


def test_pr_manipulations(repo, app, org, base_url):
    inst = github.Github(base_url=base_url, auth=app.iat(org, {'contents': 'write'}))
    r = inst.get_organization(org.login).get_repo(repo.name)
    default = r.get_git_ref('heads/' + r.default_branch)

    r.create_git_ref('refs/heads/other', default.object.sha)
    r.create_file("foo", "a message", "some content", branch='other')['commit']

    inst = github.Github(
        base_url=base_url,
        auth=(
            auth := app.iat(
                org,
                {'pull_requests': 'write', 'contents': 'read'},
            )
        ),
        lazy=True,  # to avoid the need for i:r
    )
    r = inst.get_organization(org.login).get_repo(repo.name)
    pr = r.create_pull(r.default_branch, 'other', title="title")
    assert pr.title == 'title'
    pr.update()

    issue = pr.as_issue()
    c = issue.create_comment("a comment")
    for c in issue.get_comments():
        pass
    issue.add_to_labels("foo", "bar")
    c.create_reaction('heart')
    issue.edit(state='closed', state_reason='duplicate')

    pr.edit(maintainer_can_modify=False)
    for _ in pr.get_reviews():
        pass
    for _ in pr.get_commits():
        pass

    s = requests.Session()
    s.headers['Authorization'] = f'token {auth.token}'
    res = s.post(
        f"{base_url}/graphql",
        json={
            'query': '''\
query ($owner: String!, $name: String!, $pr: Int!) {
    repository(owner: $owner, name: $name) {
        pullRequest(number: $pr) {
            closingIssuesReferences(last: 100) {
                nodes {
                    number
                    repository {
                        nameWithOwner
                    }
                }
            }
        }
    }
}
''',
            'variables': {
                'owner': r.owner.login,
                'name': r.name,
                'pr': pr.number,
            },
        },
    )
    assert res.ok, res.text
    results = res.json()
    assert 'errors' not in results, results['errors']
    # todo: add ref so it's not empty?
    assert (
        results['data']['repository']['pullRequest']['closingIssuesReferences']['nodes']
        == []
    )


def test_statuses(app, org, repo, base_url):
    inst = github.Github(
        base_url=base_url, auth=app.iat(org, {'contents': 'read', 'statuses': 'read'})
    )
    r = inst.get_organization(org.login).get_repo(repo.name)
    default = r.get_git_ref('heads/' + r.default_branch)
    st = r.get_commit(default.object.sha).get_combined_status()
    assert st.state == 'pending'
    assert st.statuses == []


def test_deployments(app, org, repo, base_url):
    inst = github.Github(
        base_url=base_url,
        auth=app.iat(org, {'deployments': 'write', 'contents': 'read'}),
    )
    r = inst.get_organization(org.login).get_repo(repo.name)
    default = r.get_git_ref('heads/' + r.default_branch)
    d = r.create_deployment(
        default.ref,
        description="whatever",
        task='something',
        auto_merge=False,
        required_contexts=[],
    )
    d.create_status(
        state='success',
        target_url=default.object.url,
        description='a description',
    )


def test_git_interations(tmp_path, app, org, repo, base_url):
    """The mergebot needs to clone/pull/push content via git, it should be
    pretty straightforward but should still be tested for safety.

    The only oddball thing is AFAIK using an IAT for git requires using the
    `x-access-token` pseudo-user.

    (actually there could be a problem with branch protection, looks like
    IATs don't have ways to bypass branch protection?)
    (apparently not, github apps can be added to bypass rules, so should
    work, but that's more reason to test it)
    """
    inst = github.Github(
        base_url=base_url, auth=(auth := app.iat(org, {'contents': 'write'}))
    )
    repo_path = tmp_path / 'repo'
    url = urlsplit(base_url)
    netloc = 'github.com' if url.netloc == 'api.github.com' else url.netloc
    url = url._replace(
        netloc=f"x-access-token:{auth.token}@{netloc}", path=repo.full_name
    )
    subprocess.run(
        ['git', '-c', 'protocol.http.allow=always', 'clone', url.geturl(), repo_path],
        check=True,
    )
    with repo_path.joinpath('foo.txt').open('w') as f:
        f.write("whee")
    subprocess.run(['git', '-C', repo_path, 'add', 'foo.txt'])
    subprocess.run(['git', '-C', repo_path, 'commit', '-m', "my commit"], check=True)
    subprocess.run(
        ['git', '-c', 'protocol.http.allow=always', '-C', repo_path, 'push'], check=True
    )

    r = inst.get_organization(org.login).get_repo(repo.name)
    c = r.get_commit('refs/heads/' + r.default_branch)
    assert c.commit.message == 'my commit'


def test_cross_pr(is_github, app, org, repo, user, base_url):
    """Because IATs can only work within an owner's scope, UATs are necessary
    to create pull requests between different owners (accounts), which for
    mergebot is every PR as the dev branches (forward-port branches) live
    in a different repository than the reference repos

    Also because =FUN= it's straight up not possible to do cross-owner forks via
    github apps even with UAT, and I really don't want to give private repos
    access to my PAT, so request fork from the user instead.
    """
    app.authorize(user)
    auth = github.Github(base_url=base_url, auth=app.uat(user))
    # need to do that before prompting to fork, otherwise we'll never see the fork
    app.install(user)
    r = auth.get_repo(repo.full_name)
    if is_github:
        existing_forks = {repo.full_name for repo in r.get_forks()}
        webbrowser.open(repo.html_url + '/fork')
        for _ in range(10):
            time.sleep(10)
            forks = {repo.full_name for repo in r.get_forks()}
            if new := (forks - existing_forks):
                break
        else:
            raise TimeoutError(f"Never found fork of {repo.full_name}")
        fork = auth.get_repo(new.pop())
    else:
        # DC just allows that because I'm not going to implement these stupid limitations
        fork = r.create_fork()

    fork.create_file("foo", "a message", "some content")['commit']
    pr = r.create_pull(
        r.default_branch,
        fork.owner.login + ':' + fork.default_branch,
        title="cross repo pr",
    )
    assert [c.commit.message for c in pr.get_commits()] == ['a message']
    assert [f.filename for c in pr.get_commits() for f in c.files] == ['foo']
