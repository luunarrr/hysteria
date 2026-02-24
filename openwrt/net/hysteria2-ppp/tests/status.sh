#!/bin/sh
# Exercises the link status collector in files/hysteria-ppp-statuslib.
#
#   sh openwrt/net/hysteria2-ppp/tests/status.sh
#
# Runs anywhere with a POSIX shell. Like tests/claim-pool.sh it is worth running
# under more than one, because the collector reads its inputs with the shell's
# own parameter expansion and BusyBox ash is stricter than bash about several of
# the forms involved:
#
#   for sh in dash bash busybox\ sh; do $sh tests/status.sh; done
#
# Three of these guard things that would not merely misreport but would take the
# whole page down, or say the opposite of the truth:
#
#   Test 2  a server address containing a quote produces a document no parser
#           accepts. That does not corrupt one field, it blanks every interface
#           on the page including the ones that are fine -- and server addresses
#           are free-text operator strings that nothing validates.
#   Test 3  an interface name reaches a path. rpcd hands over whatever the ubus
#           request contained.
#   Test 5  a state file left behind by a previous claimant reports a link as
#           carrying traffic when the process that wrote it is long gone. That
#           residue is the ordinary case, not an edge one: once pppd exits, the
#           claim names a pid that answers nothing and clearing it belongs to the
#           reaper rather than to the supervisor that is dying.

SELF_DIR=$(dirname "$0")
FILES="$SELF_DIR/../files"

# shellcheck disable=SC1090,SC1091
. "$FILES/hysteria-ppp-common"
# shellcheck disable=SC1090,SC1091
. "$FILES/hysteria-ppp-statuslib"

BASE=$(mktemp -d) || exit 1
trap 'rm -rf "$BASE"' EXIT

# Everything the collector reads, redirected into a scratch directory. Every
# function under test is the real one; only where it looks changes.
hysteria_status_run_dir() { echo "$BASE"; }
hysteria_claims_dir()     { echo "$BASE/hysteria-$1.claims"; }
hysteria_rotor_file()     { echo "$BASE/hysteria-$1.rotor"; }
hysteria_meta_file()      { echo "$BASE/hysteria-$1.meta"; }
hysteria_gate_file()      { echo "$BASE/hysteria-$1.bundle"; }
hysteria_sup_pid()        { echo "$BASE/hysteria-$1-sup$2.pid"; }
hysteria_slot_yaml()      { echo "$BASE/hysteria-$1-$2.yaml"; }
hysteria_slot_state()     { echo "$BASE/hysteria-$1-$2.state"; }
hysteria_slot_client()    { echo "$BASE/hysteria-$1-$2.client"; }
hysteria_slot_lasterr()   { echo "$BASE/hysteria-$1-$2.lasterr"; }
hysteria_slot_bytes()     { echo "$BASE/hysteria-$1-$2.bytes"; }

# Frozen, so that an ageing test is a test rather than a race with the clock.
NOW=100000
hysteria_uptime() { echo "$NOW"; }

# Driven rather than read from /sys: the suite has no interface to point at.
DEVICE_UP=1
hysteria_status_device_up() { [ "$DEVICE_UP" = 1 ]; }

# The same, for the bundle device's kernel counters. DEVICE_STATS empty is the
# case where the device exists but the statistics directory cannot be read, which
# has to leave the fields out rather than emit an empty one.
DEVICE_STATS=1
hysteria_status_device_stat() {
	[ "$DEVICE_STATS" = 1 ] || return 1
	case "$2" in
	rx_bytes) printf '4096' ;;
	tx_bytes) printf '2048' ;;
	rx_packets) printf '40' ;;
	tx_packets) printf '20' ;;
	*) return 1 ;;
	esac
}

CFG=wan
fail=0

chk() {
	if [ "$2" = "$3" ]; then
		echo "  ok   $1"
	else
		echo "  FAIL $1: got '$2' want '$3'"
		fail=1
	fi
}

# The state of one link, pulled back out of the document. Enough of a reader for
# a test; the shipped CLI does the same thing for the same reason.
link_state() {
	printf '%s' "$1" | sed -n "s/.*\"slot\":$2,\\([^}]*\\).*/\\1/p" |
		sed -n 's/.*"state":"\([a-z]*\)".*/\1/p'
}

# An interface-level field, read from the document down to the links array.
#
# Scoped rather than matched across the whole of it, because this sed is greedy
# and returns the LAST match in what it is given -- and a link now carries
# rx_bytes and tx_bytes under the same names the interface does. Unscoped, an
# assertion about the interface's counters would be satisfied by a link's, and
# would pass just as happily if the collector emitted no interface counters at
# all. The shipped CLI scopes the same way and for the same reason.
top() {
	printf '%s' "${1%%'"links":'*}" | sed -n "s/.*\"$2\":\\([0-9a-z\"]*\\).*/\\1/p" | tr -d '"'
}

reset() {
	rm -rf "$BASE"
	mkdir -p "$BASE" "$(hysteria_claims_dir "$CFG")"
	DEVICE_UP=1
	{
		echo "ifname=hy-wan"
		echo "multilink=1"
		echo "slots=3"
		echo "mtu=1399"
		echo "bundle_mtu=1393"
		echo "bundle=hysteria-wan"
	} > "$(hysteria_meta_file "$CFG")"
	: > "$(hysteria_gate_file "$CFG")"
	local n=1
	while [ "$n" -le 3 ]; do
		echo "server: 'srv$n.example.com:443'" > "$(hysteria_slot_yaml "$CFG" "$n")"
		n=$((n + 1))
	done
}

# A slot held by this shell -- a pid that is certainly alive -- carrying traffic.
seed_carrying() {
	local n="$1" role="${2:-member}"
	ln -sfn "$$" "$(hysteria_claims_dir "$CFG")/$n"
	{
		echo "pid=$$"
		echo "role=$role"
		echo "state=running"
		echo "since=$((NOW - 600))"
		echo "joined=1"
		echo "join_by=link-attached"
	} > "$(hysteria_slot_state "$CFG" "$n")"
	echo "state=up" > "$(hysteria_slot_client "$CFG" "$n")"
}

# What a slot's client publishes about what it carried.
seed_bytes() {
	local n="$1" rx="$2" tx="$3" hist="${4:-10:20,30:40}"
	{
		echo "pid=$$"
		echo "rx=$rx"
		echo "tx=$tx"
		echo "rxpkts=7"
		echo "txpkts=3"
		echo "for=600"
		echo "histstep=1000"
		echo "hist=$hist"
	} > "$(hysteria_slot_bytes "$CFG" "$n")"
}

# One link's field, pulled back out of the document. Scoped to the slot rather
# than matched across the whole string, because several links carry the same key
# and a greedy match would report the last one for every row.
link_field() {
	printf '%s' "$1" | sed -n "s/.*\"slot\":$2,\([^{}]*\).*/\1/p" |
		sed -n "s/.*\"$3\":\([0-9]*\).*/\1/p"
}

# --- 1. the ordinary bundle -------------------------------------------------

reset
seed_carrying 1 holder
seed_carrying 2
doc=$(hysteria_status_json "$CFG")
chk "1a. a joined link is carrying" "$(link_state "$doc" 1)" "carrying"
chk "1b. links_up counts only what is up" "$(top "$doc" links_up)" "2"
chk "1c. an unclaimed slot is idle" "$(link_state "$doc" 3)" "idle"
chk "1d. bundle_state is formed" "$(top "$doc" bundle_state)" "formed"
chk "1e. for is derived from since" \
	"$(printf '%s' "$doc" | sed -n 's/.*"for":\([0-9]*\).*/\1/p' | head -1)" "600"

# --- 2. a server address that would break the document ----------------------

reset
printf 'server: %s\n' "\"ev'il\\\\srv\".example.com:443" > "$(hysteria_slot_yaml "$CFG" 1)"
seed_carrying 1
doc=$(hysteria_status_json "$CFG")
# Every quote inside the value must be preceded by a backslash, and every
# backslash doubled. Checked by counting: an unescaped quote closes the string
# early and the rest of the object becomes syntax.
bad=$(printf '%s' "$doc" | sed -n 's/.*"server":"\([^,]*\)".*/\1/p' |
	sed -e 's/\\\\//g' -e 's/\\"//g' | tr -cd '"\\')
chk "2a. quotes and backslashes in a server address are escaped" "$bad" ""
chk "2b. the document still parses as one link" "$(link_state "$doc" 1)" "carrying"

# --- 3. names that reach a path ---------------------------------------------

reset
if hysteria_status_json "../../etc/passwd" >/dev/null 2>&1; then
	chk "3a. a traversing interface name is refused" "accepted" "refused"
else
	echo "  ok   3a. a traversing interface name is refused"
fi
if hysteria_status_json "wan;reboot" >/dev/null 2>&1; then
	chk "3b. a name with a metacharacter is refused" "accepted" "refused"
else
	echo "  ok   3b. a name with a metacharacter is refused"
fi
if hysteria_status_json "" >/dev/null 2>&1; then
	chk "3c. an empty name is refused" "accepted" "refused"
else
	echo "  ok   3c. an empty name is refused"
fi

# --- 4. the join verdict is never guessed -----------------------------------

reset
seed_carrying 1
# The verdict left open: an unrecognised pppd never writes either marker.
{
	echo "pid=$$"
	echo "role=member"
	echo "state=dialling"
	echo "since=$((NOW - 60))"
} > "$(hysteria_slot_state "$CFG" 1)"
doc=$(hysteria_status_json "$CFG")
chk "4a. transport up with no verdict is connected, not carrying" \
	"$(link_state "$doc" 1)" "connected"

# Refused by the bundle: authenticated, then turned away. The state that used to
# be indistinguishable from working.
{
	echo "pid=$$"
	echo "role=member"
	echo "state=refused"
	echo "since=$((NOW - 60))"
	echo "joined=0"
} > "$(hysteria_slot_state "$CFG" 1)"
doc=$(hysteria_status_json "$CFG")
chk "4b. a refused join is refused, not carrying" "$(link_state "$doc" 1)" "refused"

# --- 5. residue from a previous claimant ------------------------------------

reset
seed_carrying 1
# The claim moves to somebody else while the old state file is still there.
ln -sfn 999998 "$(hysteria_claims_dir "$CFG")/1"
doc=$(hysteria_status_json "$CFG")
chk "5a. state whose pid disagrees with the claim is not believed" \
	"$(link_state "$doc" 1)" "idle"

reset
seed_carrying 1
# The claim itself names a process that no longer exists, which is what a slot
# looks like between a pppd exiting and the pool reaping it.
ln -sfn 999999 "$(hysteria_claims_dir "$CFG")/1"
doc=$(hysteria_status_json "$CFG")
chk "5b. a dead claim is not a carrying link" "$(link_state "$doc" 1)" "idle"
chk "5c. links_up excludes it" "$(top "$doc" links_up)" "0"

# --- 6. why a server is not carrying ----------------------------------------

reset
{
	echo "code=LNS_UNREACHABLE"
	echo "at=$((NOW - 120))"
	echo "detail=no LNS answered"
} > "$(hysteria_slot_lasterr "$CFG" 3)"
doc=$(hysteria_status_json "$CFG")
chk "6a. a recent failure makes an idle slot retrying" "$(link_state "$doc" 3)" "retrying"

# A reason that waiting cannot fix is not "retrying" -- netifd has already
# stopped, and saying otherwise is a plain untruth.
echo "code=AUTH_FAILED
at=$((NOW - 120))" > "$(hysteria_slot_lasterr "$CFG" 3)"
doc=$(hysteria_status_json "$CFG")
chk "6b. a permanent reason is blocked, not retrying" "$(link_state "$doc" 3)" "blocked"

# Old enough not to be the current explanation any more.
echo "code=LNS_UNREACHABLE
at=$((NOW - 100000))" > "$(hysteria_slot_lasterr "$CFG" 3)"
doc=$(hysteria_status_json "$CFG")
chk "6c. a stale failure is forgotten" "$(link_state "$doc" 3)" "idle"

# A server that is carrying now is not described by why it failed before.
reset
seed_carrying 2
echo "code=LNS_UNREACHABLE
at=$((NOW - 60))" > "$(hysteria_slot_lasterr "$CFG" 2)"
doc=$(hysteria_status_json "$CFG")
chk "6d. a carrying link keeps its state despite an old failure" \
	"$(link_state "$doc" 2)" "carrying"

# --- 7. the bundle as a whole -----------------------------------------------

reset
rm -f "$(hysteria_gate_file "$CFG")"
doc=$(hysteria_status_json "$CFG")
chk "7a. device up with no gate means the peer refused multilink" \
	"$(top "$doc" bundle_state)" "refused"

reset
DEVICE_UP=0
doc=$(hysteria_status_json "$CFG")
chk "7b. no device means the bundle is down" "$(top "$doc" bundle_state)" "down"

# A gate file left behind by a holder that was killed outright must not be read
# as a live bundle. This is the case the members' own gate check exists for.
reset
DEVICE_UP=0
doc=$(hysteria_status_json "$CFG")
chk "7c. a stale gate without a device is not a formed bundle" \
	"$(top "$doc" bundle_state)" "down"

# --- 8. single-server interfaces --------------------------------------------

reset
rm -rf "$(hysteria_claims_dir "$CFG")"
rm -f "$(hysteria_gate_file "$CFG")"
{
	echo "ifname=hy-wan"
	echo "multilink=0"
	echo "slots=1"
	echo "mtu=1399"
	echo "servers_ignored=2"
} > "$(hysteria_meta_file "$CFG")"
doc=$(hysteria_status_json "$CFG")
chk "8a. no pool and a live device reads as connected" "$(link_state "$doc" 1)" "connected"
chk "8b. bundle_state is off" "$(top "$doc" bundle_state)" "off"
chk "8c. servers configured but unused are still counted" \
	"$(top "$doc" servers_ignored)" "2"

# --- 9. a slot count out of a file is input, not fact ------------------------

# "sed -i" is not portable -- GNU takes no argument, BSD requires one -- and this
# suite is meant to run under whatever is to hand.
meta_slots() {
	local file
	file=$(hysteria_meta_file "$CFG")
	sed "s/^slots=.*/slots=$1/" "$file" > "$BASE/m"
	mv "$BASE/m" "$file"
}

reset
meta_slots 9999
doc=$(hysteria_status_json "$CFG")
chk "9a. an absurd slot count is clamped" "$(top "$doc" links_configured)" "16"

reset
meta_slots banana
doc=$(hysteria_status_json "$CFG")
chk "9b. a non-numeric slot count falls back to one" \
	"$(top "$doc" links_configured)" "1"

# --- 10. recording why a server failed ---------------------------------------

# The reason a link ended is written by hysteria_lasterr_write, and for most
# failures there is no detail to go with the code: only an LNS-supplied message
# fills that field, so a dial that simply timed out has a code and nothing else.
# That was exactly the case the writer used to discard -- a trailing
# "[ -n "$detail" ] && printf" made the whole write group report failure, and the
# temporary file was deleted rather than renamed. A server failing every 36
# seconds for an hour showed a blank reason on the page.
reset
hysteria_lasterr_write "$CFG" 2 "LINK_DOWN" ""
chk "10a. a reason with no detail is still recorded" \
	"$(sed -n 's/^code=//p' "$(hysteria_slot_lasterr "$CFG" 2)" 2>/dev/null)" "LINK_DOWN"

hysteria_lasterr_write "$CFG" 3 "LNS_UNREACHABLE" "no LNS answered"
chk "10b. a reason with detail keeps the detail" \
	"$(sed -n 's/^detail=//p' "$(hysteria_slot_lasterr "$CFG" 3)" 2>/dev/null)" "no LNS answered"

# And it has to reach the page, not just the disk.
reset
hysteria_lasterr_write "$CFG" 3 "LINK_DOWN" ""
doc=$(hysteria_status_json "$CFG")
chk "10c. a detail-less failure surfaces as retrying" "$(link_state "$doc" 3)" "retrying"

# --- 11. an interface that was never set up ---------------------------------

reset
rm -f "$(hysteria_meta_file "$CFG")"
if hysteria_status_json "$CFG" >/dev/null 2>&1; then
	chk "11a. an interface with no meta file fails" "succeeded" "failed"
else
	echo "  ok   11a. an interface with no meta file fails"
fi

# --- 12. what each server carried -------------------------------------------

# The figures a bundle has no other source for. The kernel keeps byte counters on
# the bundle unit and none at all on a member channel, so if these do not come
# from the clients they do not exist.
reset
seed_carrying 1 holder
seed_carrying 2
seed_bytes 1 111111 222
seed_bytes 2 333 444
doc=$(hysteria_status_json "$CFG")
chk "12a. a link reports what it carried" "$(link_field "$doc" 1 rx_bytes)" "111111"
chk "12b. and in the other direction" "$(link_field "$doc" 1 tx_bytes)" "222"
chk "12c. each link reports its own figure" "$(link_field "$doc" 2 rx_bytes)" "333"
chk "12d. packets come through too" "$(link_field "$doc" 1 rx_packets)" "7"
chk "12e. the sample step is published" "$(link_field "$doc" 1 hist_step_ms)" "1000"
chk "12f. the rate series is passed through verbatim" \
	"$(printf '%s' "$doc" | sed -n 's/.*"slot":1,\([^{}]*\).*/\1/p' |
		sed -n 's/.*"hist":"\([^"]*\)".*/\1/p')" "10:20,30:40"

# A link that never came up publishes nothing, and the collector must not invent
# a zero for it: zero is a claim that the link carried nothing, and the truth is
# that there is no link to ask.
chk "12g. a link with no client file reports no figure" "$(link_field "$doc" 3 rx_bytes)" ""

# --- 13. a byte file left behind by a dead claimant --------------------------

# The same residue problem as test 5, on the file that would be read as the
# current throughput of a server that is not connected at all.
reset
seed_carrying 1
seed_bytes 1 999999 888888
# The claim now names somebody else, so the slot's whole session record is stale.
ln -sfn 999999 "$(hysteria_claims_dir "$CFG")/1"
doc=$(hysteria_status_json "$CFG")
chk "13a. a stale byte file is discarded" "$(link_field "$doc" 1 rx_bytes)" ""
chk "13b. and the link is not reported as carrying" "$(link_state "$doc" 1)" "idle"

# --- 13b. a byte file whose session never came up ----------------------------

# The gap the claim check cannot see. .state and .client are rewritten by every
# attempt, so a stale one is replaced as soon as a new process claims the slot --
# but .bytes is only written once a session comes up, so a client that claims the
# slot and then fails its handshake for ten minutes leaves its predecessor's file
# underneath a claim that is genuinely current. Without a second gate the row
# would report a dialling link as carrying the traffic the last one carried.
reset
seed_bytes 1 777777 666666
ln -sfn "$$" "$(hysteria_claims_dir "$CFG")/1"
{
	echo "pid=$$"
	echo "role=holder"
	echo "state=dialling"
	echo "since=$((NOW - 30))"
} > "$(hysteria_slot_state "$CFG" 1)"
doc=$(hysteria_status_json "$CFG")
chk "13c. a link that is not up reports no figure" "$(link_field "$doc" 1 rx_bytes)" ""
chk "13d. and is still reported as dialling" "$(link_state "$doc" 1)" "dialling"

# --- 14. a byte file that is not a number ------------------------------------

# The one place text from a file leaves this collector as a JSON number. An
# unchecked value puts a bare word where a number belongs, which does not corrupt
# one field -- it makes the whole document unparseable and blanks every interface
# on the page.
reset
seed_carrying 1
{
	echo "pid=$$"
	echo "rx=; DROP TABLE"
	echo "tx=12"
} > "$(hysteria_slot_bytes "$CFG" 1)"
doc=$(hysteria_status_json "$CFG")
chk "14a. a non-numeric byte count is dropped" "$(link_field "$doc" 1 rx_bytes)" ""
chk "14b. the numeric field beside it survives" "$(link_field "$doc" 1 tx_bytes)" "12"
chk "14c. and the document still parses" "$(link_state "$doc" 1)" "carrying"

# --- 15. the bundle device's own counters ------------------------------------

# What Network -> Interfaces shows for this interface. One netdev per bundle, so
# this is the sum of every link and belongs at the top level rather than in a row.
reset
seed_carrying 1 holder
doc=$(hysteria_status_json "$CFG")
chk "15a. the interface reports its own RX" "$(top "$doc" rx_bytes)" "4096"
chk "15b. and its own TX" "$(top "$doc" tx_bytes)" "2048"
chk "15c. and packets" "$(top "$doc" rx_packets)" "40"

# A device that is down has no counters to report, and a zero would read as an
# interface that is up and carrying nothing.
reset
DEVICE_UP=0
doc=$(hysteria_status_json "$CFG")
chk "15d. a down interface reports no counters" "$(top "$doc" rx_bytes)" ""

# Nor may an unreadable statistics directory produce an empty field.
reset
DEVICE_STATS=0
doc=$(hysteria_status_json "$CFG")
chk "15e. unreadable statistics leave the fields out" "$(top "$doc" rx_bytes)" ""
chk "15f. and the document still parses" "$(top "$doc" bundle_state)" "formed"

exit $fail
