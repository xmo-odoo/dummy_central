""" Immediately submitted inline comments.

Comments associated with a review are sub-objects of that review.

Top-level comments are issue comments.
"""

def test_review_comments(repo, pr):
    head = repo.get_commit(pr.head.sha)
    c = pr.create_review_comment('what', head, 'foo', 1)
    assert pr.get_review_comment(c.id).body == 'what'
    c.edit('xxx')
    pr.create_review_comment('wheee', head, 'foo', 1)
    assert [c.body for c in pr.get_review_comments()] == [
        'xxx',
        'wheee'
    ]
    c.delete()
    assert [c.body for c in pr.get_review_comments()] == ['wheee']