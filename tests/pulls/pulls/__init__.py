# TODO: https://github.com/isaacs/github/issues/361
#       validate that the reply holds (and that reopening otherwise works):
#
# We're blocking the pull request reopen if the current head isn't a
# descendant of the stored head sha (which is what the head was when
# the pull request was closed). We are not allowing the reopen in
# that case, because there is no good way to tell what changes have
# happened while a pull request was closed and the head branch has changed.
#
# also: per https://github.com/isaacs/github/issues/361#issuecomment-590633932
# might be possible to make the PR reopenable by pushing back the closure head
# so this is not a permanent lock, it's revertible
