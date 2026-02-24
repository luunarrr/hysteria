#!/bin/sh
# Exercises the slot claim pool in files/hysteria-ppp-common.
#
#   sh openwrt/net/hysteria2-ppp/tests/claim-pool.sh
#
# Runs anywhere with a POSIX shell -- the pool uses nothing but ln, readlink, rm,
# mkdir and kill -0, so it can be checked without a router. Worth running under
# more than one shell: the double-booking race this guards against was invisible
# under dash and reproduced immediately under bash, because the window it opens
# is only as wide as the scheduler makes it.
#
#   for sh in dash bash busybox\ sh; do $sh tests/claim-pool.sh; done
#
# Test 6 is the one that matters. An earlier version of the pool claimed a slot
# with mkdir and then wrote the owner's pid into a file inside it, leaving a
# window in which the claim existed with no owner recorded. A second claimant
# arriving in that window read no pid, concluded the slot was abandoned, and took
# it -- so twelve claimants over six slots issued seven, and two pppd would dial
# the same access concentrator. The fix was to make the claim a symlink whose
# target is the pid, so that creating it and recording its owner are one atomic
# step.

SELF_DIR=$(dirname "$0")
. "$SELF_DIR/../files/hysteria-ppp-common"

BASE=$(mktemp -d) || exit 1
trap 'rm -rf "$BASE"' EXIT

# The only thing overridden: the files live somewhere writable rather than in
# /var/run. Every function under test is the real one.
#
# The last two are here because releasing a slot also drops the state describing
# it, and a test suite that reaches into /var/run on the machine running it is
# one that behaves differently on a router than on a laptop.
hysteria_claims_dir()  { echo "$BASE/hysteria-$1.claims"; }
hysteria_rotor_file()  { echo "$BASE/hysteria-$1.rotor"; }
hysteria_slot_state()  { echo "$BASE/hysteria-$1-$2.state"; }
hysteria_slot_client() { echo "$BASE/hysteria-$1-$2.client"; }

CFG=t
D=$(hysteria_claims_dir "$CFG")
fail=0

chk() {
	if [ "$2" = "$3" ]; then
		echo "  ok   $1"
	else
		echo "  FAIL $1: got '$2' want '$3'"
		fail=1
	fi
}

reset() { rm -rf "$D" "$BASE/hysteria-$CFG.rotor"; mkdir -p "$D"; }

# Twelve claimants over "count" slots, all started as close to simultaneously as
# the shell allows. seed_dead=1 pre-fills every slot with a dead owner, which is
# what forces the reap path.
contend() {
	local count="$1" seed_dead="$2" k=1
	reset
	if [ "$seed_dead" = 1 ]; then
		while [ "$k" -le "$count" ]; do ln -s 999991 "$D/$k"; k=$((k + 1)); done
	fi
	: > "$OUT"
	local i=0
	while [ "$i" -lt 12 ]; do
		( s=$(hysteria_claim_slot "$CFG" "$count") && echo "$s" >> "$OUT" ) &
		i=$((i + 1))
	done
	wait
}

reset
a=$(hysteria_claim_slot "$CFG" 3)
b=$(hysteria_claim_slot "$CFG" 3)
c=$(hysteria_claim_slot "$CFG" 3)
chk "1. claims are distinct and ascending" "$a$b$c" "123"

if d=$(hysteria_claim_slot "$CFG" 3); then
	chk "2. claiming past the count fails" "claimed $d" "refused"
else
	echo "  ok   2. claiming past the count fails"
fi

hysteria_release_slot "$CFG" 2
chk "3. a released slot is reusable" "$(hysteria_claim_slot "$CFG" 3)" "2"

# A claim whose owner is gone must be recoverable, or one SIGKILL costs a server
# for the lifetime of the interface.
reset; ln -s 999999 "$D/1"
chk "4. a claim with a dead owner is reaped" "$(hysteria_claim_slot "$CFG" 2)" "1"

# ...and one whose owner is alive must not be.
reset; ln -s $$ "$D/1"
chk "5. a claim with a live owner is left alone" "$(hysteria_claim_slot "$CFG" 2)" "2"

OUT=$BASE/out

# The race, on a pool that starts empty: only the creation path is exercised.
contend 6 0
chk "6. empty pool: no slot issued twice" "$(sort "$OUT" | tr -d '\n')" "$(sort -u "$OUT" | tr -d '\n')"
chk "7. empty pool: exactly as many winners as slots" "$(wc -l < "$OUT" | tr -d ' ')" "6"

# The race on the REAP path, which is the one that matters and the one the suite
# used to miss entirely. Every slot starts owned by a pid that no longer exists,
# which is the ordinary residue of a holder whose transport died -- so this is
# the hot path, not an edge case. An earlier version passed tests 6 and 7 while
# double-booking here in every single round.
#
# Repeated, because a race that reproduces "usually" is a race that a single
# green run says nothing about.
round=1
while [ "$round" -le 12 ]; do
	contend 6 1
	got=$(sort "$OUT" | tr -d '\n')
	uniq=$(sort -u "$OUT" | tr -d '\n')
	if [ "$got" != "$uniq" ]; then
		chk "8. reap path round $round: no slot issued twice" "$got" "$uniq"
		break
	fi
	if [ "$(wc -l < "$OUT" | tr -d ' ')" != "6" ]; then
		chk "8. reap path round $round: exactly as many winners as slots" \
			"$(wc -l < "$OUT" | tr -d ' ')" "6"
		break
	fi
	round=$((round + 1))
done
[ "$round" -gt 12 ] && echo "  ok   8. reap path: 12 rounds, no double-booking"

# A slot whose server is down must not pin every claimant to it. The rotor is
# what stops the dialer -- the only claimant that can run before a bundle exists
# -- from taking slot 1 on every single attempt and never reaching the others.
reset
first=$(hysteria_claim_slot "$CFG" 3); hysteria_release_slot "$CFG" "$first"
second=$(hysteria_claim_slot "$CFG" 3); hysteria_release_slot "$CFG" "$second"
third=$(hysteria_claim_slot "$CFG" 3); hysteria_release_slot "$CFG" "$third"
chk "9. successive claims rotate rather than repeat" "$first$second$third" "123"

# Retargeting hands a claim to the process that actually holds the server.
reset
sl=$(hysteria_claim_slot "$CFG" 2)
hysteria_claim_retarget "$CFG" "$sl" 424242
chk "10. retarget repoints the claim" "$(readlink "$D/$sl")" "424242"
HY_CLAIM_PID=""
hysteria_release_slot "$CFG" "$sl"
chk "11. release does not free a retargeted claim it no longer owns" \
	"$(readlink "$D/$sl")" "424242"

# Releasing someone else's claim must be a no-op, or a slow process cleaning up
# after being reaped would evict whoever took over from it.
reset; ln -s 999999 "$D/1"
hysteria_release_slot "$CFG" 1
chk "12. releasing a claim we do not hold does nothing" "$(readlink "$D/1")" "999999"

exit $fail
