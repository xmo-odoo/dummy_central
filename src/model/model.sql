-- a network of git repositories, all forks share a network
CREATE TABLE network (
    id integer primary key
) STRICT;

-- FIXME: turns out forks do *not* just share their objects in a big pile,
--        instead it looks like something trickier occurs.
CREATE TABLE objects (
    -- ??? normally the PK should be the sha, but because of the network that
    -- does not actually work, which is a problem...
    id integer not null primary key,
    network integer not null references network ON DELETE CASCADE,
    sha blob not null check (length(sha) = 20),
    data blob not null,
    -- from a repo it's possible to find any object in its network (e.g. create
    -- a ref or whatever), but we don't want to find cross-repo objects
    unique(sha, network)
) STRICT;

CREATE TABLE users (
    id integer primary key,
    login text not null unique,
    name text,
    type text not null check (type in ('user', 'organization')),
    -- default default branch for repos
    default_branch text not null default 'main'
) STRICT;

INSERT INTO users (login, name, type)
VALUES ('ghost', 'Deleted user', 'user'),
       ('web-flow', 'GitHub Web Flow', 'user');

CREATE TABLE emails (
    email text not null primary key,
    user integer not null references users ON DELETE CASCADE,
    "primary" integer check ("primary" in (0, 1)),
    visibility text not null check (visibility in ('public', 'private'))
    -- github has email verification
    -- unclear how to manage visibility on an individual basis, once validated
    -- it seems to be all or nothing at the account level
) STRICT;
CREATE UNIQUE INDEX emails_unique_primary_per_user
    ON emails(user)
 WHERE "primary";

CREATE TABLE tokens (
    id integer primary key,
    token text not null unique,
    user integer not null references users ON DELETE CASCADE
) STRICT;

CREATE TABLE repositories (
    id integer primary key,
    owner integer not null references users ON DELETE CASCADE,
    name text not null,
    network integer not null references network,
    -- also a source for the original forked repo?
    -- FIXME: what happens if you fork a fork then your parent is deleted?
    parent integer references repositories ON DELETE SET NULL ,
    visibility integer not null check (visibility in (0, 1)) default 1,
    -- base branch for PRs and commits
    default_branch text not null,
    -- number of the last created issue / pr
    issue_seq integer not null default 0,
    unique(owner, name)
) STRICT;

CREATE TABLE refs (
    name text not null,
    repository integer not null references repositories on delete cascade,
    object integer not null references objects,

    unique(repository, name)
) STRICT;

CREATE TABLE acl (
    id integer primary key,
    label varchar not null
);
INSERT INTO acl (id, label)
VALUES (1, 'read'),
       (2, 'triage'),
       (3, 'write'),
       (4, 'maintain'),
       (5, 'admin');
CREATE TRIGGER create_acl INSERT ON acl BEGIN SELECT raise(ABORT, 'list of ACLs is read-only'); END;
CREATE TRIGGER update_acl UPDATE ON acl BEGIN SELECT raise(ABORT, 'list of ACLs is read-only'); END;
CREATE TRIGGER delete_acl DELETE ON acl BEGIN SELECT raise(ABORT, 'list of ACLs is read-only'); END;

-- should probably have a flag to indicate the invitation was accepted (q:
-- does it need 3 values to store rejection info? could just delete if declined)
CREATE TABLE collaborators (
    repository integer not null references repositories on delete cascade,
    user integer not null references users on delete cascade,
    -- TODO: should this link to a join table with the repo in order to handle
    --       variable list of permissible ACLs?
    role integer not null references acl,
    unique(repository, user)
) STRICT;

CREATE TABLE rulesets (
    id integer primary key,
    created_at text not null default current_timestamp,
    updated_at text not null default current_timestamp,

    repository integer not null references repositories on delete cascade,

    name text not null,
    target text not null check (target in ('branch', 'tag', 'commit')),
    enforcement text not null check (enforcement in ('disabled', 'active')),
    unique(repository, name)
) STRICT;

CREATE TABLE ruleset_conditions (
    ruleset integer not null references rulesets on delete cascade,
    -- if not include then exclude
    include integer not null check (include in (0, 1)) default true,
    condition text not null
) STRICT;

CREATE TABLE ruleset_rules (
    ruleset integer not null references rulesets on delete cascade,
    type text not null check (type in ('creation', 'update')),
    parameters text -- json blob
) STRICT;

CREATE TABLE statuses (
    id integer primary key,
    -- created_at datetime not null default current_timestamp,
    -- updated_at datetime not null default current_timestamp, ???
    object integer not null references objects on delete cascade,
    state text not null check(state in ('error', 'failure', 'pending', 'success')),
    context text not null default 'default',
    target_url text,
    description text,
    -- creator references users
    unique(object, context)
) STRICT;

CREATE TABLE issues (
    id integer primary key,
    repository integer not null references repositories ON DELETE CASCADE,
    -- TODO: how to handle numbering?
    number integer not null,
    state text not null check(state in ('open', 'closed')),
    -- TODO: non-owner user fields should be assigned the ghost user on deletion
    user integer references users on delete set null,
    title text not null,
    body text,
    unique(repository, number)
) STRICT;

CREATE TABLE labels (
    id integer primary key,
    name text not null unique,
    color text not null,
    description text
) STRICT;

CREATE TABLE issue_labels (
    issue integer not null references issues on delete cascade,
    label integer not null references labels on delete cascade,
    unique(issue, label)
) STRICT;


CREATE TABLE issue_comments (
    id integer primary key,
    issue integer not null references issues on delete cascade,
    body text not null,
    user integer references users on delete set null,

    created_at text not null default (datetime()),
    updated_at text not null default (datetime())
) STRICT;

-- `head` and `base` are somewhat similar, but all fields of `base`
-- are actually required, which is not the case for `repo`:

-- per github types I apparently don't remember, the `repo` is
-- nullable on the head (if the fork was deleted e.g. #47640), as not
-- documented (or supported) if user account was deleted then label
-- and user are also dropped (#51976)

-- on base only the actual branch is needed because the user & repo
-- are the current (unless / until the db is moved out of the repo)
-- the label can be regenerated from user + branch, and the head is
-- trivially the current head of the branch in the repo EZ

CREATE TABLE pull_requests (
    issue integer primary key references issues on delete cascade,
    head integer not null references objects,
    label text not null, -- $owner:$branch (generated, remains even if other fields are deleted)
    -- source
    branch text not null,
    -- is the owner necessary when we have the repo?
    owner integer references users on delete set null,
    repository integer references repositories on delete set null,
    -- dest
    base text not null,
    draft integer not null default false,
    dead integer not null default false
) STRICT;

-- m2m table of closing references between PRs and issues (the issues may be PRs)
CREATE TABLE closing_references (
    pr integer not null references pull_requests on delete cascade,
    issue integer not null references issues on delete cascade,

    UNIQUE (issue, pr)
) STRICT;
CREATE INDEX closing_references_pull_requests
    ON closing_references (pr);

CREATE TABLE reviews (
    id integer primary key,
    -- references PRs rather than issues to avoid mis-association
    pull_request integer not null references pull_requests on delete cascade,
    body text not null,
    author integer references users on delete set null,
    state text not null check(state in ('approve', 'request_changes', 'comment', 'pending')),
    commit_id integer not null references objects,

    submitted_at text not null default (datetime())
) STRICT;

CREATE TABLE review_comments (
    id integer primary key,
    pull_request integer not null references pull_requests on delete cascade,
    body text not null,

    created_at text not null default (datetime()),
    updated_at text not null default (datetime()),

    path text not null,
    position integer check(line > 0),
    line integer check(line > 0),
    side text check(side in ('left', 'right')),
    start_line integer check(start_line < line),
    start_side text check(start_side in ('left', 'right')),

    -- note: review comment can be freestanding, part of a review, or in reply
    -- to an other comment
    -- TODO: can a comment be both in reply and associated with a review?
    review integer references reviews on delete cascade,
    -- FIXME: when replying to a comment, and the original gets deleted, does
    --        the new one just become toplevel? How about multiple?
    in_reply_to integer references review_comments on delete set null,

    CHECK ( position is null != line is null
        AND line is null = side is null
        AND ((line is not null and start_line is not null and start_side is not null)
          OR coalesce(start_line, start_side) is null)
    )
) STRICT;

-- not sure what the global webhook data model should be
CREATE TABLE repository_webhooks (
    id integer primary key,
    repository integer not null references repositories on delete cascade,
    active integer not null default 1 check (active in (0, 1)),
    content_type text not null default 'form' check (content_type in ('json', 'form')),
    url text not null,
    events text not null default "push",
    insecure_ssl integer not null default 0 check (insecure_ssl in (0, 1)),
    secret text not null default "",
    last_response_code integer,
    last_response_status text,
    last_response_message text,

    UNIQUE (repository, url)
) STRICT;