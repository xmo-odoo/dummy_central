# permissions

This is not specific to apps, but since FGTs are not implemented it's only
relevant to apps. I should probably implement scopes for classic pats while at
it.

## ACL checking

Of course permissions are only relevant if they're checked, so this would also
warrant implementing ACL checking. One thing I've not solved (for myself) is
how to ensure ACLs get checked at the top of every handler.

idea: maybe should be a prereq to getting the actor out of the auth? So part of
`get_actor_by_id`, and something similar in stead of `user::Auth::user` /
`install::Auth::installation`?

# installation_repository webhook

The access span of installations is currently unused and unsupported, but if it
ever is relevant this hook needs to be dispatched when creating (or deleting) a
repository which is visible by an application.

Might need to have an internal event system to avoid circular dependencies / the
continued intermixing of various concers.
