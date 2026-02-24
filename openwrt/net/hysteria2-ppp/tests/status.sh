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

# Frozen, so that an ageing test is a test rather than a race with the clock.
NOW=100000
hysteria_uptime() { echo "$NOW"; }

# Driven rather than read from /sys: the suite has no interface to point at.
DEVICE_UP=1
hysteria_status_device_up() { [ "$DEVICE_UP" = 1 ]; }

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

top() {
	printf '%s' "$1" | sed -n "s/.*\"$2\":\\([0-9a-z\"]*\\).*/\\1/p" | tr -d '"'
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

exit $fail
