#!/bin/sh

[ -x /usr/sbin/pppd ] || exit 0
[ -x /usr/bin/hysteria2-ppp ] || exit 0
# Sourced further down for the server claim pool. Guarded here with the rest
# because netifd globs this directory once at startup: a source that fails takes
# the whole file with it, and the protocol would be missing from the dropdown
# with nothing logged to say why.
[ -r /usr/libexec/hysteria2-ppp-common ] || exit 0

# INCLUDE_ONLY is assigned on its own line, and a second flag answers "am I the
# top-level script", because those are two different questions and the obvious
# way of writing this gets the second one wrong.
#
# "INCLUDE_ONLY=1 . ./ppp.sh" looks like it scopes the assignment to that one
# command, but "." is a POSIX special built-in, and an assignment prefixed to a
# special built-in persists in the shell afterwards. INCLUDE_ONLY would still be
# set at the bottom of this file, add_protocol would never run, and netifd would
# never learn this protocol exists -- while LuCI, which registers the protocol
# client-side, would still offer it and accept a full configuration for it.
#
# This is the structure upstream uses in comgt's 3g.sh for the same reason.
[ -n "$INCLUDE_ONLY" ] || {
	NOT_INCLUDED=1
	INCLUDE_ONLY=1

	. /lib/functions.sh
	. /lib/functions/network.sh
	. ../netifd-proto.sh
	. ./ppp.sh
	init_proto "$@"
}

# Multilink PPP across several access concentrators.
#
# One PPP link is one pppd. That is not an implementation detail to work around:
# MP is a bundle of independent links, each running its own LCP and its own
# authentication, joined through a host-wide database rather than by any of them
# being told about the others. N servers therefore means N pppd, and netifd holds
# exactly one process per interface -- a second proto_run_command SIGKILLs the
# incumbent rather than adding to it -- so only one of them can be netifd's.
#
# That one owns the network device, because it is the process that created the
# PPP unit and there is no way to hand a unit over. Its death is a full interface
# rebuild, which is the correct netifd semantic. What it is NOT is tied to a
# particular server: it dials whatever the claim pool gives it, and when its own
# transport dies it stays alive holding the bundle while a supervisor redials
# that server as an ordinary member. No link is worth more than any other.
. /usr/libexec/hysteria2-ppp-common

# How many servers one interface will bundle. Bounds the cleanup sweep in
# hysteria_links_stop, which has to run without knowing the previous config.
HYSTERIA_MAX_LINKS=16

hysteria_link_env() { echo "/var/run/hysteria-$1.link"; }
hysteria_gate_file() { echo "/var/run/hysteria-$1.bundle"; }
hysteria_sup_pid() { echo "/var/run/hysteria-$1-sup$2.pid"; }

hysteria_yaml_quote() {
	# printf, not echo: BusyBox is built with FEATURE_FANCY_ECHO, so echo eats a
	# leading -n/-e/-E. This handles the auth token, the obfuscation password and
	# the camouflage secret.
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"
}

# pppd's options-file grammar: double quotes with backslash escapes. Used for
# the holder's option file below, and mirrored by ppp_quote in hysteria-ppp-link
# for the members'.
hysteria_ppp_quote() {
	printf '"%s"' "$(printf '%s' "$1" | sed -e 's/[\\"]/\\&/g')"
}

# The shell sink, matching hysteria_yaml_quote for the YAML one. A value that
# crosses into a file which then gets sourced must have its single quotes
# rewritten as the '\'' dance -- the only form a POSIX shell reads back
# unchanged.
#
# Not cosmetic. These values are free-form operator strings from plain LuCI text
# fields, validated by nothing. An apostrophe in a PPP password ends the quoted
# string early, and "." is a special builtin, so the syntax error takes the whole
# supervisor down at its source line -- before its log() exists, with stderr
# already on /dev/null. Every member dies silently while the holder comes up
# fine, because pppd is handed the password as an argv word with no second
# parse: an interface at one link's throughput, forever, with nothing logged.
# A value containing "';" would run as root, once per supervisor.
hysteria_env_line() {
	printf "%s='%s'\n" "$1" "$(printf '%s' "$2" | sed "s/'/'\\\\''/g")"
}

# hysteria_validate prints a reason code and fails for a configuration that
# cannot work, so setup can name it and stop rather than redial on it forever.
#
# Every case here is one the client itself does not catch. Two of them are worse
# than a rejected config: the client starts, the interface comes up, and the
# connection silently never establishes.
hysteria_validate() {
	case "$obfs_type" in
	"" | plain) ;;
	salamander | gecko)
		# Both wrap the packet with a keyed cipher, so neither works without one.
		[ -n "$obfs_password" ] || {
			echo "OBFS_PASSWORD_MISSING"
			return 1
		}
		;;
	*)
		echo "OBFS_TYPE_INVALID"
		return 1
		;;
	esac

	if [ -n "$camouflage_secret" ]; then
		# The server refuses this pairing outright: camouflage recognises a flow
		# by its QUIC header, and obfuscation is precisely what hides that
		# header. The client does not check, so without this the link comes up
		# and simply never connects.
		case "$obfs_type" in
		"" | plain) ;;
		*)
			echo "OBFS_WITH_CAMOUFLAGE"
			return 1
			;;
		esac
		# The client requires both halves of the camouflage config; a secret on
		# its own is a startup failure with nothing to point at.
		[ -n "$camouflage_server_ip" ] || {
			echo "CAMOUFLAGE_INCOMPLETE"
			return 1
		}
	fi

	return 0
}

# hysteria_write_config writes one client configuration. Everything except the
# server address is shared by every link in a bundle: the links differ only in
# which access concentrator they cross, and the subscriber the LNS authenticates
# is the same one either way.
#
# The Hysteria2 credential in particular must be identical on every link. The
# concentrator picks an LNS by hashing the subscriber's Hysteria2 identity, which
# is what makes independent concentrators choose the same one; two identities may
# hash apart, and links that reach different LNS cannot be bundled by either.
hysteria_write_config() {
	local file="$1"
	local srv="$2"

	rm -f "$file"
	touch "$file" || return 1
	chmod 600 "$file" || return 1

	echo "server: $(hysteria_yaml_quote "$srv")" >> "$file"
	[ -n "$auth" ] && echo "auth: $(hysteria_yaml_quote "$auth")" >> "$file"

	if [ -n "$sni" ] || [ "$insecure" = 1 ] || [ -n "$pin_sha256" ] || [ -n "$ca" ]; then
		echo "tls:" >> "$file"
		[ -n "$sni" ] && echo "  sni: $(hysteria_yaml_quote "$sni")" >> "$file"
		[ "$insecure" = 1 ] && echo "  insecure: true" >> "$file"
		[ -n "$pin_sha256" ] && echo "  pinSHA256: $(hysteria_yaml_quote "$pin_sha256")" >> "$file"
		[ -n "$ca" ] && echo "  ca: $(hysteria_yaml_quote "$ca")" >> "$file"
	fi

	if [ -n "$hop_interval" ]; then
		echo "transport:" >> "$file"
		echo "  type: udp" >> "$file"
		echo "  udp:" >> "$file"
		echo "    hopInterval: $(hysteria_yaml_quote "$hop_interval")" >> "$file"
	fi

	# Each obfuscation type keeps its settings under a key named after itself, so
	# the block is named from the type rather than assuming one of them. Writing a
	# gecko password under a salamander key is silent: the client reads no
	# password for the type it was told to use, and the link never connects.
	case "$obfs_type" in
	"" | plain) ;;
	*)
		echo "obfs:" >> "$file"
		echo "  type: $(hysteria_yaml_quote "$obfs_type")" >> "$file"
		echo "  $obfs_type:" >> "$file"
		echo "    password: $(hysteria_yaml_quote "$obfs_password")" >> "$file"
		if [ "$obfs_type" = "gecko" ]; then
			[ -n "$obfs_gecko_min_size" ] && echo "    minPacketSize: $obfs_gecko_min_size" >> "$file"
			[ -n "$obfs_gecko_max_size" ] && echo "    maxPacketSize: $obfs_gecko_max_size" >> "$file"
		fi
		;;
	esac

	if [ -n "$bandwidth_up" ] || [ -n "$bandwidth_down" ]; then
		echo "bandwidth:" >> "$file"
		[ -n "$bandwidth_up" ] && echo "  up: $(hysteria_yaml_quote "$bandwidth_up")" >> "$file"
		[ -n "$bandwidth_down" ] && echo "  down: $(hysteria_yaml_quote "$bandwidth_down")" >> "$file"
	fi

	[ "$fast_open" = 1 ] && echo "fastOpen: true" >> "$file"

	if [ -n "$camouflage_secret" ]; then
		echo "camouflage:" >> "$file"
		echo "  secret: $(hysteria_yaml_quote "$camouflage_secret")" >> "$file"
		[ -n "$camouflage_server_ip" ] && echo "  serverIP: $(hysteria_yaml_quote "$camouflage_server_ip")" >> "$file"
	fi

	echo "ppp:" >> "$file"
	echo "  mode: nospawn" >> "$file"
	echo "  dataStreams: ${data_streams:-0}" >> "$file"
	# The MRU pppd is being started with. In nospawn mode the client is pppd's
	# pty child, so pppd fixed this before the client existed and nothing the
	# client measures could change it -- telling it the number instead means it
	# skips a path measurement that would cost up to five seconds per dial and
	# arrive somewhere it cannot be applied. It is also the better figure to give
	# the server, being what pppd actually uses rather than an inference.
	echo "  mtu: $mtu" >> "$file"

	return 0
}

proto_hysteria_init_config() {
	ppp_generic_init_config
	proto_config_add_string "server"
	# Additional access concentrators, one PPP link each, bundled with the first
	# by Multilink PPP at the LNS. There is no ordering significance: "server" is
	# simply the one an operator configures first, and losing it costs exactly
	# what losing any other costs.
	#
	# An array rather than a string, and that is the part worth getting right.
	# uci's __uci_element_to_blob skips a UCI_TYPE_LIST option outright when the
	# policy says string -- no error, no warning, the option simply never arrives.
	# Declaring it as an array is what makes "list extra_server" reachable at all;
	# it is the same bug openwrt/packages fixed in bonding.sh by turning
	# proto_config_add_string "slaves" into proto_config_add_array.
	#
	# Bare name, no ":type" suffix. netifd splits the name at the colon and keeps
	# the remainder as a UCI datatype for validation only -- it never reaches the
	# blobmsg type, and array elements are strings regardless, because netifd does
	# not populate the info[] that would say otherwise.
	proto_config_add_array "extra_server"
	proto_config_add_string "multilink"
	proto_config_add_string "endpoint"
	proto_config_add_string "bundle"
	proto_config_add_string "auth"
	proto_config_add_string "sni"
	proto_config_add_boolean "insecure"
	proto_config_add_string "pin_sha256"
	proto_config_add_string "ca"
	proto_config_add_string "obfs_type"
	proto_config_add_string "obfs_password"
	proto_config_add_int "obfs_gecko_min_size"
	proto_config_add_int "obfs_gecko_max_size"
	proto_config_add_string "bandwidth_up"
	proto_config_add_string "bandwidth_down"
	proto_config_add_string "hop_interval"
	proto_config_add_boolean "fast_open"
	proto_config_add_int "data_streams"
	proto_config_add_string "camouflage_secret"
	proto_config_add_string "camouflage_server_ip"
	proto_config_add_string "config_file"
	available=1
	no_device=1
	# Without this netifd discards whatever proto_notify_error reports, so the
	# reasons this handler goes to the trouble of extracting -- AUTH_FAILED and
	# the rest -- would never reach ifstatus, and LuCI would show a bare "link
	# down" for every one of them. Every protocol in ppp.sh sets it.
	lasterror=1
}

hysteria_extra_servers=""

hysteria_collect_extra_server() {
	# json_for_each_item passes the value first. Empty entries are what a LuCI
	# DynamicList leaves behind when a row is cleared rather than removed.
	[ -n "$1" ] && hysteria_extra_servers="$hysteria_extra_servers $1"
}

# hysteria_have_multilink reports whether this pppd was built with MP.
#
# OpenWrt ships two builds of the same source as mutually exclusive variants:
# "ppp", configured without --enable-multilink, and "ppp-multilink" with it. They
# install the same /usr/sbin/pppd, so the binary's name settles nothing -- but
# the multilink, mp and bundle options exist only inside
# "#ifdef PPP_WITH_MULTILINK", so asking pppd for its own option table is both
# cheap and exact, where inspecting the package list would be neither.
#
# "notty" is not optional, and its absence is why the previous form never worked
# even once. pppd looks for a device in tty_process_extra_options() and, with
# none named and stdin not a tty -- which is always, under netifd -- exits there
# with "no device specified and stdin is not a tty". That check is main.c:441;
# show-options is not consulted until :446 and dryrun not until :486, so neither
# was ever reached. The old probe reported "pppd cannot run" on every router
# alive, took its fail-open branch, and the MLPPP_UNSUPPORTED guard below has
# therefore never fired -- a router with plain "ppp" came up silently on one link
# at half the throughput, which is the exact failure the guard exists to prevent.
# It also put that option error in syslog at daemon.err on every single ifup:
# ppp_option_error() calls syslog() unconditionally, so redirecting stderr to
# /dev/null suppressed only the copy nobody was reading.
#
# "notty" makes using_pty true and returns before the device check. It allocates
# nothing: the pseudo-tty is created in connect_tty(), reached from start_link()
# long after show-options has exited.
#
# show-options rather than dryrun because dryrun prints the whole option list to
# syslog at daemon.info, while showopts() writes to stderr and exits. All that
# reaches syslog here is one "Exit." line.
hysteria_have_multilink() {
	local opts
	opts=$(/usr/sbin/pppd notty show-options 2>&1)

	# Fail open when the probe itself did not run. showopts() always prints this
	# heading -- general_options is never empty -- so its absence means pppd never
	# got that far, and that is not evidence about multilink. Refusing to bundle
	# on a pppd that can bundle is the worse error of the two: it halves the
	# throughput an operator configured, silently and permanently. Guessing
	# "capable" costs at worst one pppd option error and an exit code that
	# ppp_generic_teardown already turns into a sentence naming the real problem.
	case "$opts" in
	*"General Options:"*) ;;
	*) return 0 ;;
	esac

	# Anchored on the name column, which showopts_list() writes as
	# "    %-22s %s". Matching the bare word instead is a false positive on every
	# build, multilink or not, because master_detach is described as "Detach when
	# we're multilink master but have no link".
	printf '%s\n' "$opts" | grep -qE '^[[:space:]]+multilink[[:space:]]'
}

# hysteria_epdisc derives the endpoint discriminator every link in this bundle
# offers. The LNS decides which links belong together from the PPP username and
# this value, so all links must present the same one and it must survive a
# reboot.
#
# pppd's own default is derived from a local MAC address, which is stable and
# identical across our links -- but also identical across every other MP bundle
# on the same router, so an LNS bundling on the discriminator rather than on the
# username could merge two unrelated subscriptions. Deriving it from the
# interface and the PPP account instead keeps bundles distinct.
#
# The "local:" class prefix is not decoration. pppd parses an unprefixed value as
# a decimal class number followed by a colon, so a bare hex string is read as
# some other class with an empty value -- and every link agrees on that same
# wrong answer, which is the kind of bug that surfaces months later as "the LNS
# did not bundle us".
hysteria_epdisc() {
	local config="$1" user="$2"
	echo "local:$(printf '%s' "hysteria:$config:$user" | md5sum | cut -c1-16)"
}

# hysteria_links_stop tears down every supervisor for this interface and empties
# the claim pool.
#
# Called from teardown, and again at the top of setup: netifd can be restarted or
# killed between the two, and a supervisor left over from a previous run would
# otherwise attach a second copy of every link to the new bundle.
hysteria_links_stop() {
	local config="$1"
	local pidfile pid n=1

	while [ "$n" -le "$HYSTERIA_MAX_LINKS" ]; do
		pidfile=$(hysteria_sup_pid "$config" "$n")
		if [ -f "$pidfile" ]; then
			read -r pid < "$pidfile"
			# The supervisor traps TERM and takes its pppd down with it, so there
			# is no need to hunt for the grandchild from here.
			[ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null
			rm -f "$pidfile"
			# The supervisor normally takes its pppd down through its TERM trap,
			# but one killed outright never runs it, and pppd sets no
			# PR_SET_PDEATHSIG -- so an orphaned nodetach pppd would keep its
			# channel in the bundle with nothing able to reach it. linkname puts
			# its pid where we can.
			local gpid gpidfile
			for gpidfile in /var/run/pppd/ppp-hy-"$config"-*.pid; do
				[ -f "$gpidfile" ] || continue
				read -r gpid < "$gpidfile"
				[ -n "$gpid" ] && kill -TERM "$gpid" 2>/dev/null
			done
		fi
		rm -f "$(hysteria_slot_yaml "$config" "$n")" \
			"$(hysteria_slot_status "$config" "$n")" \
			"/var/run/hysteria-$config-sup$n.pppd" \
			/var/run/hysteria-"$config"-sup"$n"-*.pppd
		n=$((n + 1))
	done
	rm -rf "$(hysteria_claims_dir "$config")"
	rm -f "$(hysteria_link_env "$config")"
	# The gate too, and specifically here rather than only in teardown. A crash
	# leaves it behind, and a stale gate is the one piece of state that would let
	# a supervisor dial before this run's bundle exists -- the device check that
	# normally covers that is satisfied the moment the new pppd creates its unit,
	# which is before it has negotiated anything.
	rm -f "$(hysteria_gate_file "$config")"
}

proto_hysteria_setup() {
	local config="$1"

	local statusfile="/var/run/hysteria-$config.status"

	# Cleared before any path that can return, so a reason left behind by a run
	# that was killed before teardown cannot be read back as this run's verdict
	# and block a restart that would have succeeded.
	rm -f "$statusfile"

	# Same reasoning one level up: a supervisor that outlived netifd would attach
	# a duplicate of every link to the bundle this run is about to build.
	hysteria_links_stop "$config"

	local server auth sni insecure pin_sha256 ca obfs_type obfs_password
	local obfs_gecko_min_size obfs_gecko_max_size
	local bandwidth_up bandwidth_down hop_interval fast_open data_streams
	local camouflage_secret camouflage_server_ip config_file
	local multilink endpoint bundle username password keepalive pppd_options
	json_get_vars server auth sni insecure pin_sha256 ca obfs_type obfs_password \
		obfs_gecko_min_size obfs_gecko_max_size \
		bandwidth_up bandwidth_down hop_interval fast_open data_streams \
		camouflage_secret camouflage_server_ip config_file \
		multilink endpoint bundle username password keepalive pppd_options

	hysteria_extra_servers=""
	json_for_each_item hysteria_collect_extra_server extra_server

	# "auto" is the default and means "bundle if there is anything to bundle".
	# Setting it to 0 keeps extra servers in the configuration without using them,
	# which is how an operator tests one concentrator at a time.
	[ -n "$multilink" ] || multilink=auto
	local use_mp=0
	case "$multilink" in
	0 | no | off | false)
		[ -n "$hysteria_extra_servers" ] && \
			echo "hysteria: multilink disabled, ignoring extra_server" >&2
		hysteria_extra_servers=""
		;;
	1 | yes | on | true)
		use_mp=1
		;;
	*)
		[ -n "$hysteria_extra_servers" ] && use_mp=1
		;;
	esac

	if [ "$use_mp" = 1 ]; then
		# A bundle also needs a pppd that can actually be joined, which is not the
		# same as one built with multilink and is not checked here.
		#
		# OpenWrt's own 321-multilink_support_custom_iface_names.patch makes the
		# member-side lookup in mp_join_bundle() require an "IFUNIT=" field in the
		# holder's database record, and guards the only code that writes it with
		# "#ifdef USE_TDB" -- a macro pppd renamed to PPP_WITH_TDB in 2.5.0. On
		# every OpenWrt carrying pppd 2.5 or later the writer is compiled out while
		# the reader still demands it, so no member can ever join and each dies one
		# line after a successful CHAP with
		#
		#	Couldn't create ppp interface <iface>: File exists
		#
		# That is an upstream OpenWrt bug, not something this handler can route
		# around from the command line: "set FOO=bar" populates userenv_list, and
		# only script_env reaches the record. Multilink here therefore requires a
		# pppd with that ifdef corrected -- see the ppp-multilink package built
		# alongside luci-proto-hysteria.
		#
		# Deliberately not probed. The failure is invisible to this process (pppd
		# writes that line to stdout, which the supervisor discards) and the only
		# static test -- looking for the bare "IFUNIT" string in the binary --
		# reports a false negative on an unpatched upstream pppd, where multilink
		# works correctly through the older UNIT= lookup. Refusing to bundle on a
		# system that does not have the bug is worse than the bug.
		#
		# Refusing below rather than quietly dropping to a single link. A second
		# concentrator that is configured but unused looks exactly like a working
		# bundle from every status page, and the only symptom is half the
		# throughput the operator expected.
		if ! hysteria_have_multilink; then
			proto_notify_error "$config" "MLPPP_UNSUPPORTED"
			proto_block_restart "$config"
			return 1
		fi
		if [ -n "$config_file" ]; then
			# The links differ only in server address, and that address lives in
			# the generated YAML. A file supplied verbatim names one server, and it
			# cannot be reused for the others without rewriting the operator's file.
			proto_notify_error "$config" "MLPPP_CONFIG_FILE_CONFLICT"
			proto_block_restart "$config"
			return 1
		fi
		if [ -n "$data_streams" ] && [ "$data_streams" -gt 0 ] 2>/dev/null; then
			# Reliable streams and MP reassembly work against each other. The
			# receiver's budget is counted in fragments, not time: at 128 queued it
			# gives up on the hole and advances, so a retransmission arriving an
			# RTT later is discarded as already-past -- having stalled every other
			# link's fragments behind it in the meantime. A lost datagram costs one
			# packet; a stalled stream costs the whole bundle. It is also pointless
			# here, because once MRRU is negotiated every data frame carries
			# protocol 0x003D and the client's flow hash sends them all to one
			# stream regardless.
			proto_notify_error "$config" "MLPPP_DATASTREAMS_CONFLICT"
			proto_block_restart "$config"
			return 1
		fi
	fi

	# pppd defaults to an MTU of 1500 when the config does not name one, and this
	# transport cannot carry that: a QUIC datagram is capped at 1452 octets, less
	# 21 for path-MTU discovery's convergence margin and 32 for the QUIC, AEAD,
	# datagram and PPP headers, which leaves 1399. Left at 1500 a default install
	# comes up and then silently drops every full-size packet.
	#
	# ppp_generic_setup only reads mtu from the config when it is not already set,
	# so unlike pppname this can be a plain variable.
	local mtu
	json_get_var mtu mtu
	[ -n "$mtu" ] || mtu=1399

	local cfgfile slot_count=1

	if [ -n "$config_file" ]; then
		if [ ! -f "$config_file" ]; then
			proto_notify_error "$config" "CONFIG_FILE_MISSING"
			proto_block_restart "$config"
			return 1
		fi
		cfgfile="$config_file"
	else
		if [ -z "$server" ]; then
			proto_notify_error "$config" "MISSING_SERVER"
			proto_block_restart "$config"
			return 1
		fi
		local reason
		if ! reason=$(hysteria_validate); then
			proto_notify_error "$config" "$reason"
			proto_block_restart "$config"
			return 1
		fi
		# One YAML per slot. Slot numbers are positions in the pool, not a
		# ranking: which slot a given pppd dials is decided at dial time.
		local n=1 srv
		# An IPv6 literal is written [2001:db8::1]:443, and [...] is a glob pattern.
		set -f
		for srv in $server $hysteria_extra_servers; do
			[ "$n" -le "$HYSTERIA_MAX_LINKS" ] || {
				echo "hysteria: more than $HYSTERIA_MAX_LINKS servers configured, ignoring the rest" >&2
				break
			}
			if ! hysteria_write_config "$(hysteria_slot_yaml "$config" "$n")" "$srv"; then
				proto_notify_error "$config" "CONFIG_WRITE_FAILED"
				proto_block_restart "$config"
				return 1
			fi
			n=$((n + 1))
		done
		slot_count=$((n - 1))
		cfgfile=$(hysteria_slot_yaml "$config" 1)
	fi

	# ppp.sh names the device "${proto}-${config}" unless the config carries a
	# pppname, which would make this one "hysteria-wan". Default it to the shorter
	# form the LuCI page expects, and leave an operator's own choice alone.
	#
	# It goes into the config object rather than a shell variable because
	# ppp_generic_setup re-reads pppname from there before applying its own
	# default, and would overwrite anything set here.
	#
	# Truncated to what a network device name can hold. Linux allows 15
	# characters, and the kernel silently shortens anything longer -- which would
	# be survivable on its own, except that LuCI computes the same name
	# independently and would compute the untruncated one, stop recognising the
	# device as this interface's, and show a working link as down.
	#
	# The supervisors are told this name too: it is half of the gate they wait on,
	# so it has to be the name that actually reaches the kernel. That is why the
	# default is computed into a shell variable first and pushed into the config
	# object second, rather than only into the object.
	local pppname
	json_get_var pppname pppname
	[ -n "$pppname" ] || pppname="hy-$(echo "$config" | cut -c1-12)"
	json_add_string pppname "$pppname"

	# Hold on to the delegated IPv6 prefix across a reconnect. ppp.sh makes this
	# opt-in, so without it every redial releases the prefix and the LAN is
	# renumbered for a link that was only down for a moment. LuCI's PPPoE page
	# defaults it on for the same reason.
	local norelease
	json_get_var norelease norelease
	[ -n "$norelease" ] || json_add_string norelease 1

	# Adaptive LCP echo, off for a bundle.
	#
	# ppp.sh turns it on unless told otherwise (keepalive_adaptive defaults to 1)
	# and that is the right default for an ordinary link: it skips an echo
	# whenever the interface counters moved since the last one, keeping a busy
	# link quiet. The skip test reads those counters by the global ifname, and on
	# a multilink holder that name is still the empty string when LCP comes up --
	# set_ifunit() does not run until mp_join_bundle(), a moment later. So the
	# first echo asks the kernel for the statistics of an interface called "",
	# which fails four ways at once:
	#
	#   get_ppp_stats_rtnetlink: Invalid argument (line 1804)
	#   /sys/class/net//statistics/rx_bytes: No such file or directory
	#   statistics falling back to ioctl which only supports 32-bit counters
	#   Couldn't get PPP statistics: No such device
	#
	# Three errors and a warning in syslog on every successful connect, and a
	# demotion to 32-bit byte counters that outlasts the call that caused it. The
	# member links already leave adaptive out for the same reason -- see the note
	# beside lcp-echo-failure in hysteria2-ppp-link -- and this is the holder's
	# half of it. Failure detection is untouched: lcp-echo-interval and
	# lcp-echo-failure still come from keepalive, and they are what notices a link
	# going quiet.
	if [ "$use_mp" = 1 ]; then
		json_add_string keepalive_adaptive 0
	fi

	# Extra pppd options are accumulated in the positional parameters rather than
	# in a string. They are operator-supplied, and a bundle name with a space in
	# it would otherwise word-split into two more pppd options.
	#
	# $1 was captured into $config at the top, so clearing them costs nothing.
	set --

	if [ "$use_mp" = 1 ]; then
		[ -n "$endpoint" ] || endpoint=$(hysteria_epdisc "$config" "$username")

		# pppd keys a bundle on what the *peer* presented -- the name it
		# authenticated as, and the discriminator it sent. An LNS does neither: it
		# authenticates us rather than the other way round, and it need not send a
		# discriminator at all. The key can therefore collapse to something every
		# MP bundle on this router shares, and two unrelated hysteria interfaces
		# would silently merge into one.
		#
		# "bundle" is the part of that key we control. It never goes on the wire;
		# it exists to keep this interface's links to themselves.
		[ -n "$bundle" ] || bundle="hysteria-$config"

		# ppp_generic_setup appends "$@" after everything it generates, and the
		# "file" below is expanded where it sits, so everything here is parsed
		# after ppp.sh's own options. For most options that is all it takes:
		# pppd keeps the last setting, and ours is last.
		#
		# The exception is options carrying OPT_PRIO, where a value's source
		# outranks its position -- OPRIO_CMDLINE beats OPRIO_CFGFILE, so a
		# command-line setting cannot be overridden from a file at all, silently.
		# Of what we set here only "mru" is both OPT_PRIO and something ppp.sh
		# passes, and ppp.sh derives it from the same uci mtu we read below, so
		# the value it wins with is the value we wanted. The line stays because
		# ppp.sh omits mtu/mru entirely when uci does not set one, and then ours
		# is the only setting there is. multilink, mrru, bundle and endpoint are
		# also OPT_PRIO but ppp.sh never sets them, so they beat the default.
		# mtu and the four script hooks are not OPT_PRIO, so position decides and
		# ours wins.
		#
		# mtu is the bundle: six octets below what one link carries, because a
		# packet sent as a single fragment -- which is what happens whenever the
		# bundle is down to one live link -- still has to fit the transport. mru
		# and mrru stay at the link ceiling: what one link can receive is not
		# reduced by the multilink header, and lowering mru would drag the
		# advertised MRRU down with it.
		# Written to a file and passed as one "file <path>" pair, rather than as
		# thirty argv words.
		#
		# netifd hands the whole invocation to pppd through a single
		# "ubus call network.interface notify_proto" command line, and that has a
		# length ceiling. The options below had grown to sit right on it: adding
		# eight characters via pppd_options truncated the ubus argument, ubus
		# printed its usage instead of running, proto_run_command failed, and
		# netifd tore the interface down and retried -- several times a second,
		# indefinitely. A config option should never be able to do that.
		#
		# One indirection removes the ceiling entirely, and matches how member
		# links have always been configured.
		local holderopts
		holderopts="/var/run/hysteria-$config.pppd"
		rm -f "$holderopts"
		if ! touch "$holderopts" || ! chmod 600 "$holderopts"; then
			proto_notify_error "$config" "CONFIG_WRITE_FAILED"
			proto_block_restart "$config"
			return 1
		fi
		{
			echo "multilink"
			echo "bundle $(hysteria_ppp_quote "$bundle")"
			echo "endpoint $(hysteria_ppp_quote "$endpoint")"
			echo "mtu $((mtu - 6))"
			echo "mru $mtu"
			echo "mrru $mtu"
			echo "set HYSTERIA_GATE=$(hysteria_gate_file "$config")"
			echo "set HYSTERIA_BUNDLE_MTU=$((mtu - 6))"
			echo "ip-up-script /lib/netifd/hysteria-ppp-up"
			echo "ip-down-script /lib/netifd/hysteria-ppp-down"
			echo "ipv6-up-script /lib/netifd/hysteria-ppp-up"
			echo "ipv6-down-script /lib/netifd/hysteria-ppp-down"
		} >> "$holderopts"

		set -- file "$holderopts"
	fi

	# pppd runs the pty argument with execl("/bin/sh", "sh", "-c", ...), so the
	# string is word-split and glob-expanded a second time by that shell. The
	# paths are quoted for that second pass; the status file variable is what the
	# client records a terminal failure in, and teardown reads it back.
	#
	# The redirect is fd 2 and nothing else -- stdin and stdout are the pty and
	# carry PPP frames. Without it a single-link interface has the same blind spot
	# a bundle used to: pppd reports "LCP: timeout sending Config-Requests" and the
	# client's own account of why it could not reach the server goes nowhere.
	# Truncated here rather than by the client so that each attempt starts clean
	# and teardown replays only the run that just failed.
	# Conditional, because the redirect lives inside the string pppd hands to
	# "sh -c": a path that cannot be opened does not degrade to an uncaptured
	# stderr, it fails that shell and pppd gets no transport at all. A diagnostic
	# must never be able to take the link down.
	local holder_err pty_err=""
	holder_err=$(hysteria_holder_err "$config")
	rm -f "$holder_err"
	if touch "$holder_err" 2>/dev/null && chmod 600 "$holder_err" 2>/dev/null; then
		pty_err=" 2>>'$holder_err'"
	fi

	local pty_cmd="HYSTERIA_PPP_STATUS='$statusfile' /usr/bin/hysteria2-ppp client -c '$cfgfile'$pty_err"

	if [ "$use_mp" = 1 ]; then
		# Under MP this pppd does not dial a fixed server. It claims one from the
		# pool, so that losing its transport costs one link's share rather than
		# the whole bundle: it stays alive in pppd's bundle-master phase holding
		# the device, its slot returns to the pool, and a supervisor redials that
		# server as an ordinary member.
		#
		# Deliberately no "kill -TERM $PPID" here. Signalling pppd when the
		# transport dies is what turns one server's loss into a full rebuild, and
		# that is exactly the asymmetry this design removes.
		pty_cmd="/usr/libexec/hysteria2-ppp-dial '$config' '$slot_count'"
	fi

	if [ "$use_mp" = 1 ]; then
		# ppp.sh reads keepalive as "<failures> <interval>" and turns it into
		# pppd's lcp-echo pair. Members parse it the same way and use the same
		# values: under MP these echoes are per link, which makes them the only
		# thing that notices one link going quiet while the others carry on.
		local interval lcp_failure
		# The same default ppp.sh applies at its line 135, before it splits the
		# value. Omitting it is not a cosmetic difference: LuCI unsets keepalive
		# whenever both advanced fields are left blank, so a stock configuration
		# gives the holder "5 1" from ppp.sh and every member no echoes at all --
		# and a member's LCP echo is the only thing that notices its own path going
		# quiet while the bundle stays up on the others.
		[ -n "$keepalive" ] || keepalive="5 1"
		interval="${keepalive##*[, ]}"
		[ "$interval" = "$keepalive" ] && interval=5
		lcp_failure="${keepalive%%[, ]*}"

		# The supervisors are handed a file rather than an argument list. The PPP
		# password is in here, and anything a member pppd is given on its command
		# line is readable from ps by every user on the router.
		local lenv
		lenv=$(hysteria_link_env "$config")
		rm -f "$lenv"
		if ! touch "$lenv" || ! chmod 600 "$lenv"; then
			proto_notify_error "$config" "CONFIG_WRITE_FAILED"
			proto_block_restart "$config"
			return 1
		fi
		{
			hysteria_env_line HY_IFNAME "$pppname"
			hysteria_env_line HY_GATE "$(hysteria_gate_file "$config")"
			hysteria_env_line HY_BUNDLE "$bundle"
			hysteria_env_line HY_EPDISC "$endpoint"
			hysteria_env_line HY_LINK_MRU "$mtu"
			hysteria_env_line HY_BUNDLE_MTU "$((mtu - 6))"
			hysteria_env_line HY_USER "$username"
			hysteria_env_line HY_PASS "$password"
			hysteria_env_line HY_LCP_INTERVAL "$interval"
			hysteria_env_line HY_LCP_FAILURE "$lcp_failure"
			# ppp.sh applies pppd_options to the holder only, so a member link
			# inherited none of it -- and a member's LCP exchange is exactly what
			# distinguishes "did not join the bundle" from "was refused MRRU".
			# Forwarded whole rather than filtered to "debug", so that anything an
			# operator sets to diagnose the holder applies to every link.
			#
			# The supervisor emits these BEFORE its own options, so that the ones
			# a member cannot do without -- noip, noipv6, maxfail 1, the bundle
			# name -- still win. pppd takes the last occurrence of an option.
			hysteria_env_line HY_PPPD_OPTIONS "$pppd_options"
		} >> "$lenv"

		# One supervisor per configured server. With the pool holding one slot for
		# whichever pppd netifd runs, exactly one supervisor idles -- and that one
		# is what picks up the holder's server the moment its link drops.
		#
		# Detached on purpose. netifd signals the one process it started and never
		# walks the tree below it, so a supervisor that stayed this script's child
		# would simply be orphaned when the script exits; making that explicit, and
		# recording the pid, is what lets teardown reach it again.
		local sup=1
		while [ "$sup" -le "$slot_count" ]; do
			/usr/libexec/hysteria2-ppp-link "$config" "$sup" "$slot_count" >/dev/null 2>&1 &
			echo $! > "$(hysteria_sup_pid "$config" "$sup")"
			sup=$((sup + 1))
		done
	fi

	ppp_generic_setup "$config" "$@" pty "$pty_cmd"
}

proto_hysteria_teardown() {
	local config="$1"
	local statusfile="/var/run/hysteria-$config.status"
	local reason=""
	local holdererr errlines line

	# Supervisors first. They are gated on the bundle device, so they would stop
	# on their own once it goes -- but only after a poll interval, and an ifdown
	# that returns while a pppd it did not account for is still dialling is the
	# kind of thing that turns into "the interface came back up by itself".
	hysteria_links_stop "$config"

	# netifd only ever sees pppd's exit code, and a hangup looks identical whether
	# the credentials were rejected or the network dropped. The client leaves the
	# real reason here, so a failure that retrying cannot fix can be named and
	# stopped instead of looping forever.
	[ -f "$statusfile" ] && read -r reason < "$statusfile"
	rm -f "$statusfile" "$(hysteria_gate_file "$config")"

	# Say it in syslog as well as on netifd's error channel. proto_notify_error
	# writes a ubus interface error record, which ifstatus shows live and which
	# logread never sees at all -- so the reason the holder's link died was
	# readable only for as long as it stayed dead, and an outage that had already
	# recovered could not be explained from the log afterwards. Members have said
	# this for themselves all along ("link ended" in hysteria2-ppp-link); this is
	# the holder's half, and the holder is the link whose failure takes the
	# interface down.
	[ -n "$reason" ] &&
		logger -t hysteria -p daemon.warn "$config: link ended: $reason"

	# And whatever the holder's client wrote on the way out. This is the only
	# place it can be replayed: the client is pppd's pty child and dies with it,
	# so unlike a member -- whose supervisor outlives its pppd and does this for
	# it -- nothing else is left running to read the file back.
	#
	# Capped for the same reason the supervisor's replay is: a transport that
	# fails immediately makes netifd rebuild the interface every 36 seconds, and
	# an uncapped replay at each rebuild would fill the log ring with the same
	# lines and evict the "dialling" lines that name the server which failed.
	holdererr=$(hysteria_holder_err "$config")
	if [ -s "$holdererr" ]; then
		errlines=0
		while read -r line; do
			[ -n "$line" ] || continue
			errlines=$((errlines + 1))
			[ "$errlines" -le 10 ] &&
				logger -t hysteria -p daemon.warn "$config: $line"
		done < "$holdererr"
		[ "$errlines" -gt 10 ] &&
			logger -t hysteria -p daemon.warn \
				"$config: $((errlines - 10)) further stderr lines suppressed"
	fi
	rm -f "$holdererr"

	case "$reason" in
	AUTH_FAILED | NO_ROUTE)
		# The two reasons that are facts about configuration rather than about the
		# network: a Hysteria2 credential the server refused, and an identity it
		# has no LNS group for. Neither is fixed by trying again, so stop netifd
		# redialling rather than let it loop until somebody notices.
		#
		# These strings are a contract with ReasonCode.String() in the Go client
		# and with the codes luci-proto-hysteria registers for display.
		proto_notify_error "$config" "$reason"
		proto_block_restart "$config"
		;;
	"") ;;
	*)
		proto_notify_error "$config" "$reason"
		;;
	esac

	ppp_generic_teardown "$@"
}

[ -z "$NOT_INCLUDED" ] || add_protocol hysteria
