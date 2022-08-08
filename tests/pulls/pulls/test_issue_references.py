import json
import time

import github
import requests


def test_refs(
    github: github.Github, repo: github.Repository, session: requests.Session
) -> None:
    by_commit = repo.create_issue("issue a")
    by_description = repo.create_issue("issue b")
    by_merge = repo.create_issue("issue c")

    main = repo.get_commit(f'refs/heads/{repo.default_branch}')

    repo.create_git_ref('refs/heads/pr1', main.sha)
    # TODO: check variations in formatting (e.g. casing, amounts of whitespace, etc...)
    repo.create_file(
        path="foo",
        message=f"commit 1\n\nfixes #{by_commit.number}",
        content="",
        branch="pr1",
    )
    pr = repo.create_pull(
        repo.default_branch, 'pr1', title="test", body=f"fixes #{by_description.number}"
    )

    repo.merge(repo.default_branch, 'pr1', f"xxx\n\ncloses #{by_merge.number}")

    time.sleep(2.5)  # apparently github needs some time to sync this
    assert pr.update()
    assert pr.state == 'closed'

    assert by_commit.update()
    assert by_commit.state == 'closed'

    assert by_description.update()
    assert by_description.state == 'closed'

    assert by_merge.update()
    assert by_merge.state == 'closed'

    owner = json.dumps(repo.owner.login)
    name = json.dumps(repo.name)
    # TODO: test that limit (first or last) is required
    # TODO: test that limit <= 100 is required
    # TODO: only PRs to the default branch and commits which land to the default branch close PRs in github
    _, res = github.requester.graphql_query(
        f"""
query {{
    repository(owner: {owner}, name: {name}) {{
        pullRequest(number: {pr.number}) {{
            closingIssuesReferences(last: 100) {{
                nodes {{
                    number
                }}
            }}
        }}
    }}
}}
""",
        {},
    )

    linked_issues = [
        issue['number']
        for issue in res['data']['repository']['pullRequest'][
            'closingIssuesReferences'
        ]['nodes']
    ]
    assert linked_issues == [by_description.number], (
        "Only the PRs linked via the PR description (and manually via the UI which has no API) are linked"
    )
