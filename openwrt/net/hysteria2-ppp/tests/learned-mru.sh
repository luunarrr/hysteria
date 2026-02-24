#!/bin/sh
# Exercises hysteria_learned_mru in files/hysteria-ppp-common: the rule that
# decides what MRU pppd is actually started with.
#
#   sh openwrt/net/hysteria2-ppp/tests/learned-mru.sh
#
# Runs anywhere with a POSIX shell, and is worth running under more than one:
#
#   for sh in dash bash busybox\ sh; do $sh tests/learned-mru.sh; done
#
# This is the whole of the nospawn MTU story. pppd is the parent there, its MRU
# came off a command line built before the client existed, and nothing the client
# measures can reach it in that session -- so the measurement is written to a file
# and picked up here at the next bring-up. Every rule below exists because getting
# it wrong is silent: pppd comes up either way, and the only symptom is full-size
# packets disappearing.
#
# Test 3 is the one that surprises operators. Lowering the interface MTU discards
# the previous measurement rather than combining with it, because a figure
# measured against a different ceiling is not evidence about this one -- and a
# stale file that silently outranked an operator who had just changed the setting
# would be worse than no file at all.

SELF_DIR=$(dirname "$0")
. "$SELF_DIR/../files/hysteria-ppp-common"

HYSTERIA_TEST_RUN_DIR=$(mktemp -d) || exit 1
export HYSTERIA_TEST_RUN_DIR
trap 'rm -rf "$HYSTERIA_TEST_RUN_DIR"' EXIT

CFG=t
FAILED=0

# write_mtu <slot> <learned> <measured-against>
write_mtu() {
	printf 'mtu=%s\nfor=%s\n' "$2" "$3" > "$(hysteria_slot_mtu "$CFG" "$1")"
}

check() {
	_desc="$1" _want="$2" _got="$3"
	if [ "$_got" = "$_want" ]; then
		echo "ok   - $_desc (got $_got)"
	else
		echo "FAIL - $_desc: want $_want, got $_got"
		FAILED=$((FAILED + 1))
	fi
}

reset() { rm -f "$HYSTERIA_TEST_RUN_DIR"/*.mtu; }

# 1. Nothing measured yet: the configured ceiling is what pppd gets.
reset
check "no measurement falls back to the configured value" \
	1390 "$(hysteria_learned_mru "$CFG" 1390)"

# 2. A measurement taken against this exact configuration is used.
reset; write_mtu 1 1239 1390
check "a measurement against the current config is applied" \
	1239 "$(hysteria_learned_mru "$CFG" 1390)"

# 3. The operator lowered the interface MTU, so the old file measured something
#    else and must be ignored rather than combined with the new ceiling.
reset; write_mtu 1 1239 1390
check "a measurement against a different config is discarded" \
	1300 "$(hysteria_learned_mru "$CFG" 1300)"

# 4. Downward only. The client writes this file only when the negotiated figure
#    came out below what it offered, but /var/run is writable and this decides
#    what the interface comes up with.
reset; write_mtu 1 1450 1390
check "a learned value above the configured one is refused" \
	1390 "$(hysteria_learned_mru "$CFG" 1390)"

# 5. Never below what PPP allows, however the file got that way.
reset; write_mtu 1 400 1390
check "a learned value below the PPP minimum is refused" \
	1390 "$(hysteria_learned_mru "$CFG" 1390)"

# 6. Garbage is not a measurement.
reset; printf 'mtu=banana\nfor=1390\n' > "$(hysteria_slot_mtu "$CFG" 1)"
check "a non-numeric learned value is refused" \
	1390 "$(hysteria_learned_mru "$CFG" 1390)"

# 7. A bundle's links can reach their servers by different paths while pppd gives
#    them all one MRU, so the narrowest is the only figure every link can carry.
reset; write_mtu 1 1350 1390; write_mtu 2 1239 1390; write_mtu 3 1301 1390
check "the narrowest measurement across slots wins" \
	1239 "$(hysteria_learned_mru "$CFG" 1390)"

# 8. And one slot measured against a stale ceiling must not drag the rest down
#    with it -- the per-file guard has to be per file, not per interface.
reset; write_mtu 1 1239 1200; write_mtu 2 1350 1390
check "a stale slot does not narrow a bundle measured against the current config" \
	1350 "$(hysteria_learned_mru "$CFG" 1390)"

# 9. Another interface's measurements are not this one's.
reset; write_mtu 1 1239 1390
check "another interface's files are not read" \
	1390 "$(hysteria_learned_mru other 1390)"

# 10. A configured value that is not a number cannot produce one.
reset
check "a non-numeric configured value yields nothing" \
	"" "$(hysteria_learned_mru "$CFG" "")"

if [ "$FAILED" -gt 0 ]; then
	echo "$FAILED test(s) failed"
	exit 1
fi
echo "all tests passed"
