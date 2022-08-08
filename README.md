# DummyCentral: a fake git hub

## Usage

- `dummy_central`
- `users`, the `/users` configuration for the instance, a JSON object
  passed either through stdin or a file, each key is a "login" and
  maps to an object with:
  - `name`, the display name for the github user
  - `token`, an array of "tokens" (used to map / recognize / ... the
    user in API calls)
- `--port` (default=0), port to bind on, randomly selected by the os
  if left default
- `--portfile`, a file to write the port into (mostly when it's `0`)

## Purpose

Provide a better experience when testing github integration scripts and tools.

### GH issues

* github TOS doesn't allow multiple user account, so testing scenarios
  involving the interaction of multiple different users requires
  abusing their goodwill
* github's rate limit (5000/h) is quite sufficient for lots of
  "production" use but rather limited when running tests

  - secondary rate limits have made things a *lot* worse, as the
    primary objects (repositories, issues, comments) are all directly
    impacted by secondary rate limits
  - that also makes it difficult to impossible to run tests
    concurrently
* github can be rather unreliable, which would be nice to test if it
  could be reliably triggered (& protected against) but it's not and
  will fail tests randomly

  for our SUT when running the entire test suite I've taken to run
  each test thrice before declaring them failed, thank god for
  pytest-rerunfailures -- or `--sw` or `--lf` until only seemingly
  legit failures remain -- but that doesn't help with rate limits
* testing github webhooks requires the machine running the SUT to be
  accessible from the internet, traversers tend to be unreliable or
  have their own limitations, leading to either transient failures or
  rate limiting
* there is no feedback channel to be notified or aware of webhook
  deliveries, if blackbox-testing an events-based (webhooks-based)
  system this means there's no way to know that an operation has been
  propagated to the SUT, thus webhook-based workflows require
  just... waiting around, which leads to *extremely* slow test suites
  (though without these waits the rate limiting would be even more
  problematic)

#### GH errors

These are test reliability issues, but also things which it would be
useful to be able to trigger explicitely (in order to check that the
SUT reacts properly to these conditions)

* github can deliver webhooks in the wrong order (e.g. push to PR then
  retarget PR, github *can* send the retarget then the push but with
  the metadata they had when *triggered* rather than when sent
  e.g. the "commits" bit can be inconsistent)

  more generally webhook delay is unpredictable and webhooks are not
  strictly ordered even within a given repo (to say nothing of
  delivery guarantees or cross-repository anything)

  webhook can even arrive *before the API call which triggered them
  has returned* which is pretty wild
* webhooks regularly get lost e.g. runbot sends status, gh updates PR,
  webhook is never sent to the mergebot (though sometimes it might be
  a concurrency issue, there's a recurring and long-standing issue of
  db lock contention), also PR updates never reach the mergebot (user
  pushes to branch, mergebot is not notified, cf odoo/runbot#241)
* essentially any endpoint can error randomly (commonly 502 Bad
  Gateway though I think I've seen others)
* a correct result to updating a ref doesn't mean that ref is up to
  date e.g. POST/PATCH a ref, GET the ref (from the same thread), it
  can still have the old head

  and the ref update being visible through the API *doesn't mean it's
  visible through git either*: do the same as previous (including
  fetching the ref' which succeeds), check
  `https://github.com/{}.git/info/refs?service=git-upload-pack`, ref
  can be missing, SUT code currently waits up to 40s then gives up
  (assumes ref' update failed)

## Intent

Emulate the github API, *including the git service*, and additionally
provide an events back-channel to notify the caller of webhooks
deliveries.

The implementation should be entirely in-memory, but should provide
for high concurrency use (in the sense that it should be possible to
concurrently interact with many different repositories, not
necessarily that each repo should support high concurrency).

DummyCentral should be easily substitutable for github without
modifying the SUT. For this it should be possible to use `mitmproxy`
(`-M |https://api.github.com|localhost:8000`).

**WARNING**

The replacement pattern (`-M` parameter) must *not* end with a
separator, otherwise mitmproxy either:

- interprets the first segment as a nonsensical filter expression, the
  second as the match pattern, and they can never match together (plus
  if they did the domain would be replaced by an empty string)
- or if there's an explicit flow filter the terminator is interpreted
  as part of the replacement string, which generates a nonsense URL to
  hit e.g. `http://localhost:8000/|users/foo`

### Proxy Setup

Both `curl` (through `git`) and `requests` should respect the
`HTTPS_PROXY` envvars, which makes redirecting the SUT easy, the issue
is the TLS connection.

Since we already have to use mitmproxy (probably), the simplest method
seems to be [terminating using
mitmproxy](https://docs.mitmproxy.org/stable/concepts-certificates/). This,
also requires telling `requests` to use the system certstore (where we
installed mitmproxy's) rather than its own though, but that would
probably be necessary even if we did our own termination:

    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

As a result, the full configuration is

    ❯ dummy_central <params>&
    ❯ mitmdump -M '|https://(\w+\.)github.com/|http://localhost:8000/' &
    ❯ REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt ALL_PROXY=http://localhost:8080 python
    >>> import requests
    >>> requests.get('https://api.github.com/users/does-not-exist').json()
    {'message': 'Not Found', 'documentation_url': 'https://docs.github.com/rest/reference/users#get-a-user'}

**NOTE**: Telling requests to always use the system's certstore, or
using a `.env` file and
[`pytest-dotenv`](https://pypi.org/project/pytest-dotenv/) to do the
same, would work fine and avoid having to specify the option every
time

The proxy not so much as you probably want to run the test suite
against github actual from time to time, although the `.env` could set
it by default, and it could be "unset" through the CLI, that should
work using the default pytest-dotenv configuration (though not when
using `env_override_existing_values = 1`).

**WARNING**:

By default, mitmproxy will connect to the real upstream (github) in
order to look up the details of the certificate. This means connecting
to github on every request which adds round-trip time, hammers github,
and can lead to test failure (because of network or github
unreliability).

Setting `connection_strategy` to `lazy` [should prevent this
behavior](https://github.com/mitmproxy/mitmproxy/pull/5487) although
in older versions of mitmproxy you will also need to set
`upstream_cert` to `false` (so just set both in the global
configuration file always unless you have specific reasons to want
them).

**NOTES**:

- `-M` requires mitmproxy 5.2, which may not be available in all
  debian/ubuntu LTS
- `-q` can be used to avoid all output by mitmproxy if that is
  valuable.
- `-p` can be used to listen on a port other than 8080 (remember to
  update `HTTPS_PROXY`)
- `curl` apparently doesn't need a scheme to contact the proxy, but
  `requests` does
- it's probably possible to use `mitmdump` to dump (duh) the flow
  information to a file (`-w`), then reload that information in
  `mitmproxy`/`mitmweb` (`-r`) in order to diagnose failure, it *should*
  be possible to use `mitmdump` in order to filter the input

### pytest

`-o cache_dir=<path>` is *super useful* when trying to run a test
suite against e.g. DC and github actual at the same time, or
concurrently running the entire test suite and one specific test: the
pytest cache is not concurrency safe, so running the same test suite
twice at the same time will almost certainly lead to inconsistent
behaviours of sw/ff/lf/...

## Initial implementation

### raw git operations
- [x] handle `git clone --bare`
  - always sends the entire repository's content (mostly relevant to
    `fetch`)
- [x] handle `git push`
- [x] ref discovery (`{repo}/info/refs?service={service}`)
  - v1 only
  - capabilities are hardcoded bullshit

### github endpoints for mergebot
- [x] `GET /user` on the various user tokens
- [x] `GET /user/{user}` on the owner (to check whether org or user)
  - [x] `GET /user` to ensure owner account (login / name) and owner
        token match IFF the owner is a user account (aka not an org)
- [x] `POST /orgs/{owner}/repos` or `POST /user/repos` depending on owner type
- [x] `POST /repos/{repo}/hooks` to configure webhooks
- [x] `PUT /repos/{repo}/contents/{file}` to initialise the repo,
      otherwise github returns 409 conflict when trying to `POST` a
      blob or tree
- [ ] `PUT /repos/{repo}/subscription` (not actually checked so can be left out)
- [x] `POST /repos/{repo}/git/trees` (`make_commits`)
- [x] `GET /repos/{}/commits` (`log`)
- [x] `POST /repos/{repo}/git/commits` (`make_commits`)
- [x] `POST /repos/{repo}/git/refs` (`make_commits` > `make_ref`)
- [x] `POST /repos/{repo}/pulls` (`make_pr`)
- [x] `GET /repos/{repo}/pulls/{number}` (`branch`)
- [x] `PATCH /repos/{repo}/pulls/{number}` (`open`, `close`)
      done as part of `test_create_pr` (it tests a bunch of update things)
- [x] `POST /repos/{repo}/issues/{number}/comments` (`post_comment`)
- [x] `GET /repos/{repo}/issues/{number}/comments` (`comments`)
- [x] `PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}` (`edit_comment`)
- [x] `DELETE /repos/{repo}/issues/{number}/comments/{comment_id}` (`delete_comment`)
- [x] `POST /repos/{repo}/pulls/{number}/reviews` (`post_review`)
- [x] `POST /repos/{repo}/statuses/{commit}` (`post_status`)
- [x] `GET /repos/{repo}/commits/{commit}` (`commit`)
- [x] `GET /repos/{repo}/git/commits/{commit}` (`commit`)
- [x] `GET /repos/{repo}/git/trees/{tree}` (`read_tree`)
- [x] `GET /repos/{repo}/git/blobs/{blob}` (`read_tree`)
- [x] `PATCH /repos/{repo}/git/refs/{ref}` (`update_ref`)
- [x] `GET /repos/{repo}/pulls/{number}`
- [x] `POST /repos/{repo}/forks` (`fork`)
- [ ] `GET /repos/{repo}/issues/{number}/labels` (`_labels`)
- [ ] `POST /repos/{repo}/issues/{number}/labels` (`add`, `update`)
- [ ] `DELETE /repos/{repo}/issues/{number}/labels/{name}` (`discard`)
- [ ] `POST /graphql` (`draft`, so just `markPullRequestReadyForReview` and `convertPullRequestToDraft`)

key:

- `user` is the github login of a user
- `owner` is the same
- `repo` is the full name of a repository (`{owner}/{repo_name}`)
- `file` is a legal file name
- `number` is a valid issue or PR number
- `commit` is a commit SHA
- `tree` is a tree sha
- `blob` is a blob sha
- `ref` is a refname
- `name` is the name of a label

#### webhook events

- [x] `ping`
- [x] `status`
- [x] `issue_comment`
- [x] `pull_request_review`
- [x] `pull_request`
  - [x] `opened`
  - [x] `edited`
  - [x] `synchronize`
  - [x] `ready_for_review`
  - [x] `converted_to_draft`
  - [x] `closed`
  - [x] `reopened`

#### API documentation

* https://github.com/github/rest-api-description/ openapi description
  of the REST (v3) github API, rather complete (though nowhere near
  perfect) but hard to navigate /
* https://github.com/octokit/openapi-types.ts typescript type
  definitions (created from the openapi spec but a fair bit more
  readable and easier to convert, though missing details)

### Testing

* https://github.com/matusf/openapi-fuzzer could be used with the
  github openapi spec
* uses https://github.com/glademiller/openapiv3 for parsing
* there's also https://github.com/Endava/cats
* as well as https://github.com/microsoft/restler-fuzzer

### Rate-limiting

- `X-RateLimit-Remaning` / `X-RateLimit-Reset`, remaining is checked
  explicitly against `0` so setting to `1` or whatever should be fine
  until we decide to add rate-limiting testing / support
  - conditional requests don't count against rate limits if they're a
    hit (aka return a `304 Not Modified`)
- secondary rate limits may provide `Retry-After` header (in seconds, to wait)
- "large number" of updates (POST, PATCH, PUT, DELETE) should "wait at
  least one second between each request
- notifications triggers (comments, issues, PRs, ...) "may be further limited"
- rate limits trigger an HTTP 403 "Forbidden", rather than an HTTP 429
  "Too Many Requests", despite `Rate-Limit` being from the same RFC
  6585

### Tracing

* `span!(level, name, items...)` + `span.enter()` (returns a span guard)
* `trace!`, `debug!`, `info!`, `warn!`, `error!`
* `#[instrument]` for async functions, or `.instrument(...)` for (async blocks)
