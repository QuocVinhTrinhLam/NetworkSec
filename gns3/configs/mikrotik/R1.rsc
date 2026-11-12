# STATUS: ACTUAL ROUTEROS EXPORT UNAVAILABLE
#
# This file intentionally contains no RouterOS commands and must not be imported.
# The MikroTik node and the VMware GNS3 VM were powered off during collection.
# Starting them solely to run `/export` was outside the authorized operation.
# The complete node disk state is preserved in the separate offline VM backup.
#
# Required future collection command (run from an authorized maintenance session):
#   /export show-sensitive=no file=R1
# Then retrieve R1.rsc, review it for secrets, and replace this marker.
