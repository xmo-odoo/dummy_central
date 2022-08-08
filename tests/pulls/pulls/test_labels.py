import pytest


@pytest.fixture(autouse=True)
def _reset_labels(pr):
    pr.delete_labels()


def det(labels):
    return [
        {k: label[k] for k in ['color', 'default', 'description', 'name']}
        for label in labels
    ]


def default(name):
    return {
        'color': 'ededed',
        'default': False,
        'description': None,
        'name': name,
    }


def test_add_empty(pr, session):
    r = session.post(f'{pr.issue_url}/labels', json=["test"])
    assert r.ok, r.text

    r = session.post(
        f'{pr.issue_url}/labels',
        json=[],
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]

    r = session.post(
        f'{pr.issue_url}/labels',
        json={"labels": []},
    )
    assert r.status_code == 422, r.text
    # error is way too specific a validation


@pytest.mark.xfail(reason="documented in github schema, doesn't actually work")
def test_add_string(pr, session):
    r = session.post(
        f'{pr.issue_url}/labels',
        json="test",
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]


def test_add_strings(pr, session):
    r = session.post(
        f'{pr.issue_url}/labels',
        json=["test"],
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]

    r = session.post(
        f'{pr.issue_url}/labels',
        json=["bar"],
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test'), default('bar')]


def test_add_labels(pr, session):
    r = session.post(
        f'{pr.issue_url}/labels',
        json={"labels": ["test"]},
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]


def test_add_named(pr, session):
    r = session.post(
        f'{pr.issue_url}/labels',
        json=[{"name": "test"}],
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]


@pytest.mark.xfail(reason="documented in github schema, doesn't actually work")
def test_add_labels_named(pr, session):
    r = session.post(
        f'{pr.issue_url}/labels',
        json={"labels": [{"name": "test"}]},
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]


def test_set_empty(pr, session):
    r = session.put(f'{pr.issue_url}/labels', json=["test"])
    assert r.ok, r.text

    r = session.put(
        f'{pr.issue_url}/labels',
        json=[],
    )
    assert r.ok, r.text
    assert r.json() == []

    r = session.put(f'{pr.issue_url}/labels', json=["test"])
    assert r.ok, r.text
    r = session.put(
        f'{pr.issue_url}/labels',
        json={"labels": []},
    )
    assert r.ok, r.text
    assert r.json() == []


@pytest.mark.xfail(reason="documented in github schema, doesn't actually work")
def test_set_string(pr, session):
    r = session.put(
        f'{pr.issue_url}/labels',
        json="test",
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]


def test_set_strings(pr, session):
    r = session.put(
        f'{pr.issue_url}/labels',
        json=["test"],
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]

    r = session.put(
        f'{pr.issue_url}/labels',
        json=["bar"],
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('bar')]


def test_set_labels(pr, session):
    r = session.put(
        f'{pr.issue_url}/labels',
        json={"labels": ["test"]},
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]


def test_set_named(pr, session):
    r = session.put(
        f'{pr.issue_url}/labels',
        json=[{"name": "test"}],
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]


@pytest.mark.xfail(reason="documented in github schema, doesn't actually work")
def test_set_labels_named(pr, session):
    r = session.put(
        f'{pr.issue_url}/labels',
        json={"labels": [{"name": "test"}]},
    )
    assert r.ok, r.text
    assert det(r.json()) == [default('test')]


def test_delete_single_label(pr, session):
    r = session.put(
        f'{pr.issue_url}/labels',
        json=["a", "b", "c", "d"],
    )
    assert r.ok, r.text
    assert len(r.json()) == 4

    r = session.delete(f'{pr.issue_url}/labels/c')
    assert r.ok, r.text
    assert det(r.json()) == [default(n) for n in "abd"]
