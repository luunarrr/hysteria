#!/bin/sh

[ -x /usr/sbin/pppd ] || exit 0
[ -x /usr/bin/hysteria2-ppp ] || exit 0

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

hysteria_yaml_quote() {
	printf "'%s'" "$(echo "$1" | sed "s/'/''/g")"
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

hysteria_write_config() {
	local file="$1"

	rm -f "$file"
	touch "$file" || return 1
	chmod 600 "$file" || return 1

	echo "server: $(hysteria_yaml_quote "$server")" >> "$file"
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

	return 0
}

proto_hysteria_init_config() {
	ppp_generic_init_config
	proto_config_add_string "server"
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

proto_hysteria_setup() {
	local config="$1"

	local statusfile="/var/run/hysteria-$config.status"

	# Cleared before any path that can return, so a reason left behind by a run
	# that was killed before teardown cannot be read back as this run's verdict
	# and block a restart that would have succeeded.
	rm -f "$statusfile"

	local server auth sni insecure pin_sha256 ca obfs_type obfs_password
	local obfs_gecko_min_size obfs_gecko_max_size
	local bandwidth_up bandwidth_down hop_interval fast_open data_streams
	local camouflage_secret camouflage_server_ip config_file
	json_get_vars server auth sni insecure pin_sha256 ca obfs_type obfs_password \
		obfs_gecko_min_size obfs_gecko_max_size \
		bandwidth_up bandwidth_down hop_interval fast_open data_streams \
		camouflage_secret camouflage_server_ip config_file

	local cfgfile

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
		cfgfile="/var/run/hysteria-$config.yaml"
		if ! hysteria_write_config "$cfgfile"; then
			proto_notify_error "$config" "CONFIG_WRITE_FAILED"
			proto_block_restart "$config"
			return 1
		fi
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
	local pppname
	json_get_var pppname pppname
	[ -n "$pppname" ] || json_add_string pppname "hy-$(echo "$config" | cut -c1-12)"

	# Hold on to the delegated IPv6 prefix across a reconnect. ppp.sh makes this
	# opt-in, so without it every redial releases the prefix and the LAN is
	# renumbered for a link that was only down for a moment. LuCI's PPPoE page
	# defaults it on for the same reason.
	local norelease
	json_get_var norelease norelease
	[ -n "$norelease" ] || json_add_string norelease 1

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

	# pppd runs the pty argument with execl("/bin/sh", "sh", "-c", ...), so the
	# string is word-split and glob-expanded a second time by that shell. The
	# paths are quoted for that second pass; the status file variable is what the
	# client records a terminal failure in, and teardown reads it back.
	ppp_generic_setup "$config" \
		pty "HYSTERIA_PPP_STATUS='$statusfile' /usr/bin/hysteria2-ppp client -c '$cfgfile'"
}

proto_hysteria_teardown() {
	local config="$1"
	local statusfile="/var/run/hysteria-$config.status"
	local reason=""

	# netifd only ever sees pppd's exit code, and a hangup looks identical whether
	# the credentials were rejected or the network dropped. The client leaves the
	# real reason here, so a failure that retrying cannot fix can be named and
	# stopped instead of looping forever.
	[ -f "$statusfile" ] && read -r reason < "$statusfile"
	rm -f "/var/run/hysteria-$config.yaml" "$statusfile"

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
