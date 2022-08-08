Before any sort of release
--------------------------

- better testing script

  60% of the justfile is a python script (to create the users.json
  from the pytest.ini and actual github data) and the other 30% is a
  big job-management shell script, this is really not great

  **note**: make would be no better as the converter can't just rely
            on local mtimes (since it calls github)

- better running / ui, the current system setting up users via loading
  a json is not great
- tracing! currently it ~exists~ but debug is way too verbose to track
  req/res, and what's happening should be way more observable
  - can configure tower-http's tracing to change the logging level of
    req/resp
- webhooks delivery backchannel, that's a primary reason why I started
  DC in the first place!

Long term
---------

- better / easier way for third parties to *validate* tests (so they
  can write their own)

  maybe get help from github?
- split things out into multiple crates (workspace) with features so
  e.g. people who don't need graphql can not have it, and the other
  way around for people who only need gql

  split would be along the lines of:

  - git service
  - each big service center tho probably with the core repo / pr
    always enabled e.g. issues, webhooks, releases, ...
  - gql

  much of the features themselves would have to be implemented as part
  of the core model tho, so possibly this would only be a compilation
  gain (by reducing the number of routes)? tower does something like
  that, but it's *weird*
- actually support graphql
- tracking rate limits
- scenarios support!

Geological times
----------------

Track which gh features are implemented or not (and how tested they
are?)
