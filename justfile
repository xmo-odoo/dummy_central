default: format lint rlint test

# formats the entire codebase
format:
    cargo fmt
    ruff format tests

# runs python linting
lint:
    ruff check tests

# runs rust linting
rlint:
    cargo clippy


# validates the test suite against github actual, args are passed to pytest
validate users *args:
    pytest -o cache_dir=.pytest-github --users={{users}} {{args}}

# runs the test suite against a dummy_central instance (launched automatically), args are passed to pytest
[positional-arguments]
test *args:
    #!/bin/sh
    PORTFILE=$(mktemp -d)/portfile
    cargo run --release -- tests/users.json --portfile "$PORTFILE" &
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
    pytest --base-url=http://127.0.0.1:$PORT --users=tests/users.json "$@"
    RESULT=$?

    # TERM dummy_central, KILL it if it takes more than 5s to shut down
    kill $DUM_PID
    ( sleep 5; kill -9 $DUM_PID ) &
    KILLER=$!

    wait $DUM_PID
    kill -9 $KILLER

    exit $RESULT
