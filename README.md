# DummyCentral: a fake git hub

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
deliveries. Later, the ability to run scenarios (to simulate specific
github failures) should be possible. God knows how.

DummyCentral should be easily substitutable for github without
modifying the SUT. For this it should be possible to use `mitmproxy`
(`-M |https://api.github.com|localhost:8000`).

### pytest

`-o cache_dir=<path>` is *super useful* when trying to run a test
suite against e.g. DC and github actual at the same time, or
concurrently running the entire test suite and one specific test: the
pytest cache is not concurrency safe, so running the same test suite
twice at the same time will almost certainly lead to inconsistent
behaviours of sw/ff/lf/...

## Initial implementation

## Style

- `unwrap` calls should be considered todos, `expect` are congruent with 
  `unreachable!` assertions
- `todo!` are also todos

### known major limitations

- `git-upload-pack` (`git fetch`) pack negotiation over HTTP is ill
  documented and has not been characterised, so to avoid over-sending
  (by sending all repo objects all the time, which causes significant
  behavioural divergences from github) it's shunted to the dumb http
  protocol. This does cause some differences in git error messages,
  but besides that the behaviour is a lot more consistent.
- capabilities listing from ref discovery is a complete lie
- endpoints are largely just what the mergebot needs
- ACL management is basically nonexistent beyond placeholders

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