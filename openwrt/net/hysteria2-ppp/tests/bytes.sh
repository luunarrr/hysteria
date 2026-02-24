#!/bin/sh
# Exercises the byte formatter in files/hysteria-ppp-status.
#
#   sh openwrt/net/hysteria2-ppp/tests/bytes.sh
#
# Worth running under more than one shell, like the suites beside it, because the
# formatter is entirely integer arithmetic and BusyBox ash is the one that has to
# get it right:
#
#   for sh in dash bash busybox\ sh; do $sh tests/bytes.sh; done
#
# Every expectation below was produced by LuCI's own "%.2mB" -- the verbatim
# String.prototype.format out of luci-base's cbi.js, evaluated on each input --
# because matching it is the whole requirement. Network -> Interfaces renders the
# same interface with that expression, and luci-proto-hysteria's status page
# implements this same shape for the per-link columns the command line prints
# here. Three renderings of one router's throughput, which must not disagree.
#
# The cases are not a sample. They are the boundaries, because a boundary is
# where this went wrong: choosing the unit by dividing and re-testing the
# truncated quotient stops a whole unit short for every value in the thousand
# just above a boundary -- 1000500 printed "1000.50 KB" where LuCI prints
# "1.00 MB" -- and the rounding carry turned 1000999 into "1001.00 KB". The unit
# is chosen by comparing the original value against 1000^(i+1) for that reason.

SELF_DIR=$(dirname "$0")
FILES="$SELF_DIR/../files"

# Only the formatter is wanted, not the report the script prints when it runs.
# Sourcing it would need a whole scratch router; the function is self-contained,
# so it is lifted out instead. A rename here and this fails loudly, which is the
# right failure.
eval "$(sed -n '/^human() {/,/^}/p' "$FILES/hysteria-ppp-status")"

if ! command -v human >/dev/null 2>&1; then
	echo "  FAIL could not extract human() from $FILES/hysteria-ppp-status" >&2
	exit 1
fi

fail=0

chk() {
	got=$(human "$1")
	if [ "$got" = "$2" ]; then
		echo "  ok   $1 -> $got"
	else
		echo "  FAIL $1: got '$got' want '$2'"
		fail=1
	fi
}

# --- LuCI parity, boundary by boundary --------------------------------------

while read -r value expected; do
	[ -n "$value" ] || continue
	chk "$value" "$expected"
done <<'CASES'
	0 0 B
	1 1 B
	999 999 B
	1000 1000 B
	1001 1.00 KB
	1500 1.50 KB
	1999 2.00 KB
	2000 2.00 KB
	999999 1000.00 KB
	1000000 1000.00 KB
	1000001 1.00 MB
	1000500 1.00 MB
	1000999 1.00 MB
	1500000 1.50 MB
	999999999 1000.00 MB
	1000000000 1000.00 MB
	1000000500 1.00 GB
	1000999999 1.00 GB
	1234567890 1.23 GB
	8589934592 8.59 GB
	128849018880 128.85 GB
	1000000000000 1000.00 GB
	4521984317 4.52 GB
	512744192 512.74 MB
	781000000 781.00 MB
CASES

# --- input that is not a byte count -----------------------------------------

# A dash, never a zero. The collector leaves the field out entirely for a link
# that never came up, and zero would be the claim that it carried nothing.
chk "" "-"
chk "abc" "-"
chk "-5" "-"

exit $fail
