import requests
import time
from itertools import islice

import github


def _fib():
    ns = [1, 1]
    while True:
        ns.append(sum(ns))
        yield ns.pop(0)


def safe_delete(obj):
    """ Repositories can only be deleted after github has finished setting them
    up on disk, which can take some time. This retries multiple times with an
    exponential delay inbetween.

    Waits up to 5mn because `doc on forks states
    <https://docs.github.com/en/rest/repos/forks?apiVersion=2022-11-28#create-a-fork>`:

        Forking a Repository happens asynchronously. You may have to wait a
        short period of time before you can access the git objects. If this
        takes longer than 5 minutes, be sure to contact GitHub Support.
    """
    err = None
    for t in islice(_fib(), 12):
        try:
            err = None
            obj.delete()
        except github.GithubException as e:
            if e.status == 403:
                err = e
                # can't delete yet
                time.sleep(t)
                continue

            if e.status == 404:
                return

            raise
    raise err


# FIXME: this should remember repos by fullname to avoid double-deleting them
def check(req, r, delete=True):
    token = req.getfixturevalue('config')['token']
    s = requests.Session()
    s.headers['Authorization'] = f'token {token}'
    # wait up to ~2.5mn
    for t in islice(_fib(), 10):
        time.sleep(t)
        if s.head(r.url).ok:
            if delete:
                req.addfinalizer(lambda: safe_delete(r))
            return r
    raise Exception(f"Never saw resource {r.url!r}")


def pr_payload(e):
    event, payload = e
    assert event == "pull_request"
    return payload


def make_branch(repo, name):
    d = repo.get_commit(f'refs/heads/{repo.default_branch}')
    d_head = d.commit

    # tree(path: str, mode: str, type: str, content: str | sha)
    t = repo.create_git_tree([
        github.InputGitTreeElement('foo', '100644', 'blob', 'blorp'),
    ], base_tree=d_head.tree)
    c = repo.create_git_commit("a commit", t, [d_head])
    return repo.create_git_ref(f'refs/heads/{name}', c.sha)