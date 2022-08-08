# Github v3 API Types

* physical structures tries to roughly match that of the documentation
* naming conventions are
  - if the type is a schema from the API doc, try to follow that
  - otherwise root the naming in the operation's name (and add Request/Response)
  - field names should match the original, even when that requires an `r#`
  - however enums should follow Rust conventions and use `rename`
  - convenient groups of fields can be split out using
    `#[serde(flatten)]`, in which case their name should be prefixed
    by `_`
* all types should implement `Serialize` and `Deserialize` so they can
  be used on either side of the communication
* utility methods can be provided but should be type-parametric, a
  useful example is responses parameterized on some form of user or
  repository: they can't use a concrete type, but they can take
  something which either converts to what they what
  (e.g. `Into<SimpleUser>`), or can implement a relevant query trait

## Full Request Types

Currently, implements only request *bodies* (JSON), in theory could
also provide full request information? e.g. the URL, URL parameters,
query parameters, ... currently are not part of this (crate). Only the
actual request bodies (of request-bearing bodies e.g. `PUT` and
`POST`) are included.

e.g. when updating a pull request there's [`pulls::PullRequestUpdate`]
which is the information passed as a JSON body, but the actual request
also contains the repository owner, name, and PR number, passed
through the URL.

Essentially the crate currently only encodes the `requestBody` part of
the schema, but it might eventually be useful to provide an abstract
encoding of the entire request, with a possibility of implementing a
conversion to the actual requesting (or responding) API.
