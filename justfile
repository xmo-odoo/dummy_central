set positional-arguments

default: test

_users:
    #!/usr/bin/env python3
    import configparser
    import json
    import sys
    from itertools import product
    from pathlib import Path
    from urllib.request import Request, urlopen

    curdir = Path("{{justfile_directory()}}")
    # FIXME: tox and setup are only matches if they contain resp. a [pytest] and
    #        [tool:pytest] section
    for ancestor, candidate in product([curdir, *curdir.parents], ['pytest.ini', 'tox.ini', 'setup.cfg']):
        inifile = ancestor / candidate
        if inifile.is_file():
            break
    else:
        inifile = None

    jsonfile = curdir / 'users.json'

    if jsonfile.exists() and jsonfile.stat().st_mtime >= inifile.stat().st_mtime:
        sys.exit(0) # meh

    contents = {}
    c = configparser.ConfigParser(interpolation=None)
    c.read(inifile)
    for section in (c[s] for s in c.sections()):
        if 'token' not in section:
            continue

        if owner := section.get('owner'):
            contents[owner] = {
                "name": "",
                "type": "Organization",
                "token": []
            }
        if token := section['token']:
            r = urlopen(Request("https://api.github.com/user", headers={
                'Authorization': f'token {token}'
            }))
            if r.status != 200:
                print(f"Failed retrieving user data, {r.status} {r.read()!r}", file=sys.stderr)
                continue

            info = json.load(r)
            contents[info['login']] = {
                'name': '',
                'type': info['type'],
                'token': [token]
            }
    # ensure we first serialize to json, and only write if that succeeded
    jsonfile.write_text(json.dumps(contents, indent=4), encoding='utf-8')

# validates the test suite against github actual, args are passed to pytest
validate *args:
    pytest "$@"

# runs the test suite against a dummy_central instance (launched automatically), args are passed to pytest
test *args: _users
    #!/bin/sh
    PORTFILE=$(mktemp -d)/portfile
    cargo r -- users.json --portfile "$PORTFILE" &
    DUM_PID=$!

    # wait until $PORTFILE is created (or the job dies)
    while kill -0 $DUM_PID 2>/dev/null && [ ! -e $PORTFILE ]; do
        sleep 0.1
    done

    # if the job died, signal and exit
    if ! kill -0 $DUM_PID 2>/dev/null; then
        echo "dummy_central failed to start" >&2
        wait $DUM_PID
        exit $?
    fi

    PORT=$(head -n1 $PORTFILE)
    pytest --base-url=http://127.0.0.1:$PORT "$@"
    RESULT=$?

    # TERM dummy_central, KILL it if it takes more than 5s to shut down
    kill $DUM_PID
    ( sleep 5; kill -9 $DUM_PID ) &
    KILLER=$!

    wait $DUM_PID
    kill -9 $KILLER

    exit $RESULT
