# CLAT, split routing and DNS

Router settings the split-tunnel arrangement depends on. None of them are
installed by `hysteria2-ppp`: they configure dnsmasq, the firewall and the
routing policy *around* the interface, so a router that is missing them brings
the hysteria link up, reports it healthy, and still sends traffic the wrong way.
That is why they are written down — every one of them fails quietly.

Names below are from the router this was built on: the hysteria interface is
`hyena` (device `hy-hyena`), its 464xlat child is `hyena_6_4` (device
`464-hyena_6_4`), the LAN bridge is `br-lan` and the native uplink is `wwan`.
Substitute your own.

## The shape of it

The hysteria interface carries IPv6 from the LNS. LAN clients are IPv4, and a
CLAT translates for them: LAN IPv4 is policy-routed into table `100`, where the
CLAT device holds the default route, and what leaves the CLAT is IPv6 that
follows the main table into the tunnel. Destinations in the CN prefix list are
carved back out and sent to the native WAN. The router's own traffic never
enters any of this and keeps the main table, which is what lets the hysteria
client's own QUIC connection dial out over the native WAN.

Three `ip rule` entries are the whole policy:

	29000:	from all fwmark 0x8000/0x8000 iif br-lan lookup main	# CN -> native WAN
	30000:	from all iif br-lan lookup 100				# the rest -> CLAT -> tunnel
	32766:	from all lookup main					# the router itself, and the fallback

Priorities are evaluated low to high, so 29000 must stay below 30000 or the CN
carve-out never runs, and both must stay below the kernel's own main-table rule
at 32766 or neither does. (`ip rule show` may print table 100 by name — `clat` —
if an `/etc/iproute2/rt_tables` alias exists. Same table either way.)

**The whole thing fails open, deliberately.** Every rule here falls through to
main when its table is empty, and that is a requirement, not an oversight: with
the tunnel down, LAN traffic has to reach the native WAN so a captive portal can
be seen and completed — and completing the portal is what lets the tunnel come
up at all. Do not "fix" this with a blackhole route in table 100. The same
applies to DNS, which falls back to the WAN-supplied resolvers for the same
reason (§5).

## 1. Pin the NAT64 prefix

	uci add_list dhcp.@dnsmasq[0].address='/ipv4only.arpa/64:ff9b::c000:aa'
	uci commit dhcp
	/etc/init.d/dnsmasq restart

A CLAT learns the NAT64 prefix by asking for the AAAA of `ipv4only.arpa` and
reading the prefix off the synthesised answer (RFC 7050). That only works if the
resolver it reaches is doing DNS64, and if that is the operator's resolver
rather than ours, the prefix it returns is the operator's.

Answering the name locally removes the question. `64:ff9b::c000:aa` is
`192.0.0.170` inside the well-known prefix `64:ff9b::/96`, so discovery resolves
to the well-known prefix every time, on a router whose upstream does no DNS64 at
all, and before the tunnel is up.

`add_list` appends — running the block twice leaves two identical entries. Check
with `uci show dhcp.@dnsmasq[0].address`.

## 2. Populate table 100

	cat > /etc/hotplug.d/iface/99-clat-pbr <<'EOF'
	#!/bin/sh
	[ "$ACTION" = "ifup" ] || exit 0
	[ "$INTERFACE" = "hyena_6_4" ] || exit 0
	ip route replace default dev 464-hyena_6_4 table 100
	logger -t clat-pbr "table 100 default via 464-hyena_6_4 (rc=$?)"
	EOF
	chmod +x /etc/hotplug.d/iface/99-clat-pbr

This is done by hand because the declarative form does not work here. A UCI
`config route` with `option table '100'` and `option interface 'hyena_6_4'`
commits cleanly, passes `uci show`, and is then silently dropped: netifd binds a
static route to its interface **by name at config-parse time**, and `hyena_6_4`
does not exist then — it is created later at runtime by `dhcpv6.script` through
`ubus add_dynamic`. Nothing rescans static routes when a dynamic interface
appears. Table 100 simply stays empty, and because the rule fails open the
symptom is LAN traffic quietly leaving by the native WAN, not an error.

That generalises: **anything bound to the CLAT has to be event-driven.** The
device is destroyed and recreated on every tunnel flap, so a route or a firewall
rule naming it needs a hotplug hook. The `ip rule` entries are exempt — rules are
global and reference `br-lan`, which is static.

Keep one mechanism, not two. If a `config route` is still in `/etc/config/network`
alongside this hook, delete it: it does nothing today, but it will keep writing a
stale table number if the number is ever changed in UCI.

Allow ~15–25 s after `ifup hyena` before the CLAT device exists (pppd auth →
IPv6CP → DHCPv6 → 464xlat). Checking sooner shows an empty table and proves
nothing.

## 3. Split LAN traffic from router-originated traffic

	uci set network.clat_rule=rule
	uci set network.clat_rule.in='lan'
	uci set network.clat_rule.lookup='100'
	uci set network.clat_rule.priority='30000'

	uci commit network
	/etc/init.d/network reload

`in='lan'` matches on the incoming interface, which locally generated packets do
not have — so forwarded LAN traffic consults table 100 and the router's own
traffic (DNS, NTP, opkg, the hysteria client's own QUIC connection) never does.
Nothing else has to be marked, zoned or excluded.

`config rule` is the IPv4 list. No `rule6` companion is needed: LAN IPv6 already
behaves this way for free, because the source-specific default routes from the
delegated prefixes only match traffic sourced from those prefixes.

## 4. Send CN destinations out the native WAN

Two halves: fw4 marks packets whose destination is in the CN prefix list, and an
`ip rule` above the CLAT rule sends marked packets to the main table.

### The prefix list

	uclient-fetch -q -O /tmp/cn4.raw \
		https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt

	grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$' /tmp/cn4.raw \
	 | grep -vE '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|100\.6[4-9]\.|100\.[7-9][0-9]\.|100\.1[01][0-9]\.|100\.12[0-7]\.|22[4-9]\.|23[0-9]\.|24[0-9]\.|25[0-5]\.)' \
	 > /tmp/cn4.clean

	[ "$(wc -l < /tmp/cn4.clean)" -ge 3000 ] && mv /tmp/cn4.clean /etc/cn4.zone && echo OK

About 4200 prefixes. Both filters are guards rather than tidying: the first drops
anything that is not a bare CIDR so a stray line cannot abort the whole `nft`
load, the second keeps private, CGNAT, loopback, link-local and multicast space
out of a set that decides routing, and the `-ge 3000` floor is what stops a
truncated or failed download from being installed — a short list does not error,
it just silently pushes CN traffic into the tunnel.

### The mark and the rule

	uci add firewall ipset
	uci rename firewall.@ipset[-1]='cn4'
	uci set firewall.cn4.name='cn4'
	uci set firewall.cn4.family='ipv4'
	uci add_list firewall.cn4.match='dest_net'
	uci set firewall.cn4.loadfile='/etc/cn4.zone'

	uci add firewall rule
	uci rename firewall.@rule[-1]='cn_mark'
	uci set firewall.cn_mark.name='CN-direct-mark'
	uci set firewall.cn_mark.src='lan'
	uci set firewall.cn_mark.dest='*'
	uci set firewall.cn_mark.family='ipv4'
	uci set firewall.cn_mark.proto='all'
	uci set firewall.cn_mark.ipset='cn4 dest'
	uci set firewall.cn_mark.target='MARK'
	uci set firewall.cn_mark.set_xmark='0x8000/0x8000'

	fw4 check
	uci commit firewall
	fw4 reload

	uci add network rule
	uci rename network.@rule[-1]='cn_direct'
	uci set network.cn_direct.in='lan'
	uci set network.cn_direct.mark='0x8000/0x8000'
	uci set network.cn_direct.lookup='main'
	uci set network.cn_direct.priority='29000'
	uci commit network
	/etc/init.d/network reload

`loadfile` is what makes the set fw4's problem rather than ours: fw4 regenerates
it from the file on every reload, including the one that `/etc/hotplug.d/iface/20-firewall`
triggers on each ifup, so it survives redials and reboots with no hook of our own.
The cost is that editing `/etc/cn4.zone` does nothing until `fw4 reload`.

The rule lands in `mangle_prerouting` as `iifname "br-lan" ip daddr @cn4 …`,
which is the only hook early enough — the mark has to exist before the routing
decision that `ip rule` drives. Note it marks **every** packet, not just
`ct state new`. That is deliberate: the near-universal "optimisation" to
new-connection-only marking breaks return-path routing here unless conntrack
mark save/restore is added with it.

`fw4 check` before `uci commit` is worth the extra step — it validates the
generated ruleset without loading it, and a rejected ruleset means no firewall
at all.

## 5. DNS

	uci add_list dhcp.@dnsmasq[0].server='2606:4700:4700::1111'
	uci add_list dhcp.@dnsmasq[0].server='2001:4860:4860::8888'
	uci set dhcp.@dnsmasq[0].strictorder='1'
	# for captive portals
	uci set dhcp.@dnsmasq[0].rebind_protection='0'
	uci commit dhcp
	/etc/init.d/dnsmasq restart

	cat > /etc/hotplug.d/iface/99-dnsmasq-flush <<'EOF'
	#!/bin/sh
	[ "$ACTION" = "ifup" ] && [ "$INTERFACE" = "hyena_6" ] && killall -HUP dnsmasq
	EOF
	chmod +x /etc/hotplug.d/iface/99-dnsmasq-flush

The two resolvers are IPv6-only, so they are reachable through the tunnel and
not otherwise. `strictorder` is what makes them *first* rather than merely
present: by default dnsmasq queries every upstream it knows and takes whichever
answers first, and a nearby resolver beats one at the far end of the tunnel every
time — which is how `www.google.com` came back as a Facebook address. Strict
order turns the server list into policy: the entries above, then the WAN-supplied
ones netifd writes into `resolv.conf.auto`. `logread | grep "using nameserver"`
after a restart is what shows the order dnsmasq actually ended up with.

The WAN's resolvers stay in that list on purpose. They are the fallback, and the
fallback is the point: with the tunnel down the clean servers are unreachable,
dnsmasq drops to the WAN's, and both captive-portal login and the bootstrap
lookup of the hysteria server itself work through that same path. Same fail-open
principle as the routing.

`rebind_protection='0'` is a genuine trade. dnsmasq normally discards upstream
answers pointing into private address space, which is exactly what a captive
portal returns to redirect you — with protection on, the portal deadlocks.
Turning it off costs the DNS-rebinding defence for every name; if only a few
portals matter, `uci add_list dhcp.@dnsmasq[0].rebind_domain='<domain>'` exempts
them and keeps the defence everywhere else.

The flush hook exists because answers learned from the WAN resolver before the
tunnel came up are cached, and some of them are wrong. `SIGHUP` clears the cache
without restarting dnsmasq.

## Verifying

	# the prefix the CLAT will discover
	nslookup -type=AAAA ipv4only.arpa 127.0.0.1

	# rules in the right order, and table 100 actually populated
	ip rule show
	ip route show table 100        # expect: default dev 464-hyena_6_4 scope link

	# the CN set is loaded and is being hit
	nft list set inet fw4 cn4 | head
	nft list chain inet fw4 mangle_prerouting | grep -o 'packets [0-9]*'

	# upstream order strictorder is now obeying, and what the WAN contributed
	logread | grep "using nameserver"
	cat /tmp/resolv.conf.d/resolv.conf.auto

	# the three paths, which is the direct answer to "is the split working"
	ip route get 1.1.1.1  from <lan-client-ip> iif br-lan   # -> dev 464-hyena_6_4
	ip route get 39.156.66.10 from <lan-client-ip> iif br-lan   # CN -> native WAN
	ip route get 1.1.1.1                                    # router itself -> native WAN

The mangle counter is the one that catches a silently dead CN half: a zero there
after real browsing means the set is empty or the rule is not in the path, and
the symptom is only that CN traffic is slower than it should be.

Failover is worth testing once, deliberately: `ifdown hyena` should empty table
100, drop the tunnel resolver from `resolv.conf.auto`, and leave LAN clients
reaching the internet through the native WAN — including `http://captive.apple.com`
returning a portal or a success page rather than timing out.
