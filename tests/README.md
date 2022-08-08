Tests for the specific behaviour of github.

These tests can be run against github directly (default), or they can be run
against a local server, either GHE or a fake of some sort, by overriding the
`--base-url` (or `--url`).

As it is difficult (impossible?) to create users on the fly, the test suite
requires the existence of a number of users (via their API keys):

*list users here*

Tests are organised following the structure of the Github documentation, for
consistency / ease of discovery: the test suite has a directory for each
directory / document below https://docs.github.com/en/rest e.g.

    https://docs.github.com/en/rest/repos/repos

matches

    tests/repos/repos/

in which each endpoint gets its own test file, named after the anchor (which
defines the exact operation / endpoint we're trying to test) e.g.

    #update-a-repository

becomes

    test__update_a_repository.py

Technically it could be `test-update-a-repository` but that would require adding
and committing a `pytest.ini` and I don't feel like it yet.