# SPDX-License-Identifier: MIT

include $(TOPDIR)/rules.mk

PKG_NAME:=hysteria2-ppp
PKG_VERSION:=2.10.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/luunarrr/hysteria/tar.gz/refs/heads/master?
PKG_HASH:=skip
PKG_BUILD_DIR:=$(BUILD_DIR)/hysteria-master

PKG_LICENSE:=MIT
PKG_LICENSE_FILE:=LICENSE

PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/apernet/hysteria
GO_PKG_BUILD_PKG:=$(GO_PKG)/app/v2
GO_PKG_LDFLAGS_X:= \
	$(GO_PKG)/app/v2/cmd.appVersion=v$(PKG_VERSION) \
	$(GO_PKG)/app/v2/cmd.appType=release \
	$(GO_PKG)/app/v2/cmd.appPlatform=$(GO_OS) \
	$(GO_PKG)/app/v2/cmd.appArch=$(GO_ARCH)

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/hysteria2-ppp
  SECTION:=net
  CATEGORY:=Network
  TITLE:=A feature-packed proxy tool based on QUIC, with PPP support
  URL:=https://github.com/luunarrr/hysteria
  # ppp-multilink by name, rather than "whichever variant is installed".
  #
  # OpenWrt builds one source twice -- "ppp" with multilink off, "ppp-multilink"
  # with it on. They are two VARIANTs of the same directory: they install the
  # same /usr/sbin/pppd and declare no PROVIDES, no CONFLICTS and no
  # ALTERNATIVES between them.
  #
  # This was written as a pair of conditional dependencies,
  # "+PACKAGE_ppp:ppp +PACKAGE_ppp-multilink:ppp-multilink", on the reasoning
  # that a single link works with either build and that naming one would make the
  # other uninstallable alongside this package. The reasoning was sound and the
  # mechanism was not: an SDK selects both symbols, so both conditionals fire and
  # the built package asks for BOTH variants at once --
  #
  #	depends:libc ca-bundle ppp ppp-multilink
  #
  # -- which is two packages owning one file, and a dependency no resolver can
  # satisfy as written. It was invisible because it is only observable in the
  # packaged metadata, never at build time.
  #
  # Naming one build settles it, and which one is not a judgement call: bundling
  # access concentrators is what this package exists for, and testing the released
  # build confirmed it does not work without the multilink pppd.
  #
  # No @(...) Kconfig guard is needed any more. That existed because the two
  # conditionals expressed no unconditional requirement, so an image could select
  # this package with neither variant and ship no /usr/sbin/pppd at all -- at
  # which point hysteria.sh exits at its first line and the protocol is simply
  # absent from LuCI with nothing logged. A plain "+ppp-multilink" both selects
  # the package at build time and depends on it at runtime, which is the whole of
  # what that guard was standing in for.
  #
  # A router carrying stock "ppp" still has to be swapped over by hand, and no
  # packaging change here can avoid it: package-pack.mk emits "provides" into the
  # apk metadata but drops CONFLICTS entirely, so there is no way to tell apk that
  # these two replace each other. What it reports instead is the collision on
  # /usr/sbin/pppd. The description below says so.
  #
  # rpcd is named explicitly even though it is in every practical image: the link
  # status object is installed into its plugin directory, and a package that drops
  # a file into a directory owned by another package should say so. jsonfilter
  # comes from libubox, which rpcd already pulls in.
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle +rpcd +ppp-multilink
endef

define Package/hysteria2-ppp/description
  Hysteria is a feature-packed network utility optimized for networks
  of poor quality powered by a custom version of the QUIC protocol.

  This build is made from the luunarrr/hysteria master branch, which adds
  PPP over Hysteria2 and camouflage. PPP sessions are established by
  pppd, provided by the ppp-multilink package.

  Two ways to run it are installed. The hysteria init script runs it as a
  standalone service configured through /etc/config/hysteria. The netifd
  protocol handler exposes it as an interface protocol, so a hysteria link
  can be declared in /etc/config/network like any other PPP protocol and
  managed with ifup/ifdown, firewall zones and routing metrics.

  The protocol handler carries one interface over several access concentrators
  at once, bundling them with Multilink PPP at the LNS. That needs a pppd built
  with multilink, which on OpenWrt is a separate build of the same source, so
  this package depends on ppp-multilink rather than on ppp.

  The two are variants of one directory: they install the same /usr/sbin/pppd
  and neither declares a conflict with the other. That is not something the
  packaging can express -- a CONFLICTS list never reaches apk metadata -- so a
  router carrying stock ppp has to be swapped over explicitly rather than by
  dependency resolution, and until it is, what a package manager reports is the
  collision on /usr/sbin/pppd rather than anything about multilink. On an
  opkg-based image:

    opkg remove ppp --force-depends && opkg install ppp-multilink

  When building an image, select ppp-multilink instead of ppp.
endef

define Package/hysteria2-ppp/conffiles
/etc/config/hysteria
endef

# netifd globs /lib/netifd/proto/*.sh exactly once, from proto_shell_init() during
# main(), and never again -- netifd_init_script_handlers() does one glob("./*.sh")
# and popen()s each match as "<script> '' dump". A handler dropped into a running
# system is therefore invisible: "ubus call network get_proto_handlers" does not
# list it, and LuCI asks netifd for that list before it loads any protocol JS, so
# the interface protocol is simply absent from the dropdown with nothing logged.
#
# "reload" does not fix it. netifd_reload() is "return config_init_all()", which
# re-reads /etc/config/network and no more, and that is what /etc/init.d/network
# reload maps onto. Only a restart re-execs netifd and re-globs the directory.
#
# This used to end in an unconditional "ubus call network restart", and that was
# the wrong trade. What the restart buys is registration, which is needed exactly
# once -- on the first install, before any hysteria interface can exist to be
# disturbed. What it costs is every interface on the router going down, on every
# upgrade, forever: netifd_restart() is interface_set_down(NULL), which walks the
# whole interface list, and it runs inside the ubus handler before the reply. That
# bill falls due at the worst possible moment, because the router is being
# upgraded over its own network from a feed reached over that same network -- so
# the restart takes down the WAN carrying the apk transaction and the operator's
# SSH session with it, and an install that cuts the connection it arrived over
# cannot report whether it finished. It also re-execs after one second without
# killing its children, which for this package means pppd and hysteria2-ppp are
# orphaned rather than stopped, PPP teardown being nowhere near that quick.
#
# On an upgrade it buys nothing anyway. Only the script PATH is kept; netifd
# fork+execs the file fresh for every setup and teardown, so a replaced
# hysteria.sh takes effect on the next ifup with nothing restarted.
#
# One thing besides the flags IS frozen at that first glob, and it is the reason
# this is a checklist item rather than a free lunch: the "config" array of the
# dump becomes the protocol's config_params, and config_parse_interface() runs
# every hysteria section through uci_to_blob() against that cached list. An option
# not in it is dropped before the handler ever sees it. So a release that adds or
# renames a proto_config_add_* in hysteria_init_config, or changes available /
# no_device / lasterror, does need a netifd restart -- and until it happens the
# new option is silently ignored with nothing logged. Adding an option to
# hysteria.sh therefore means saying so in the release notes.
#
# So this says what happened and leaves the decision with the operator, who is the
# one who knows whether the link they are talking over can be dropped right now.
# Nothing is silently broken by waiting: an interface already configured keeps
# running on the registration netifd already has. It is also what upstream does --
# neither ppp nor wireguard-tools restarts anything from postinst, and both ship
# handlers into this same directory.
#
# IPKG_INSTROOT is non-empty while the package manager is populating an offline
# rootfs at image build time. Nothing is running to restart then, and netifd's
# first start on the real device already sees the handler.
define Package/hysteria2-ppp/postinst
[ -n "$${IPKG_INSTROOT}" ] && exit 0

# Already registered means an upgrade, and an upgrade has nothing to announce.
# jsonfilter rather than grep because get_proto_handlers returns an object keyed
# by protocol name and a substring match would accept a key that merely contains
# it; it comes from libubox, which the rpcd dependency above already pulls in. A
# scalar is selected rather than the handler object because jsonfilter prints
# nothing for a missing path either way, and a scalar makes "found" unambiguous.
# ubus not answering at all means netifd is not running, which its own next start
# resolves -- so that case takes the notice too, harmlessly.
registered=$$(ubus call network get_proto_handlers 2>/dev/null | jsonfilter -q -e '@.hysteria.no_device')
[ -n "$$registered" ] && exit 0

# Straight to stdout, not backgrounded and not through logger. apk pipes a
# script's stdout and stderr and prefixes each line, so this reaches the console;
# anything left holding those descriptors after the script exits hangs apk
# outright.
cat <<'EOF'
hysteria2-ppp: the "hysteria" interface protocol is installed but not yet
registered. netifd reads /lib/netifd/proto/ only when it starts, so the protocol
will not appear in LuCI or accept ifup until the network is restarted:

    ubus call network restart

That drops every interface on the router, including the one you are most likely
connected over. Nothing is waiting on it -- run it when that is acceptable, or
just reboot.
EOF

exit 0
endef

define Package/hysteria2-ppp/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/app $(1)/usr/bin/hysteria2-ppp

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/hysteria.init $(1)/etc/init.d/hysteria

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/hysteria.config $(1)/etc/config/hysteria

	$(INSTALL_DIR) $(1)/lib/netifd/proto
	$(INSTALL_BIN) ./files/hysteria.sh $(1)/lib/netifd/proto/hysteria.sh

	# Multilink PPP. The ip-up/ip-down wrappers chain to netifd's own scripts
	# after publishing whether a bundle was created; the dialer is the pty command
	# for the pppd netifd runs, and the link helper supervises the rest. Both of
	# the latter source the common file for the server claim pool.
	$(INSTALL_DIR) $(1)/lib/netifd
	$(INSTALL_BIN) ./files/hysteria-ppp-up $(1)/lib/netifd/hysteria-ppp-up
	$(INSTALL_BIN) ./files/hysteria-ppp-down $(1)/lib/netifd/hysteria-ppp-down

	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_DATA) ./files/hysteria-ppp-common $(1)/usr/libexec/hysteria2-ppp-common
	$(INSTALL_BIN) ./files/hysteria-ppp-dial $(1)/usr/libexec/hysteria2-ppp-dial
	$(INSTALL_BIN) ./files/hysteria-ppp-link $(1)/usr/libexec/hysteria2-ppp-link

	# Which servers a bundle is actually connected to. The collector is a library
	# with two formatters over it, rather than a formatter each, so the status
	# page and the command line cannot report different things about one router.
	# INSTALL_DATA for the library because it is sourced and never executed --
	# the same treatment the common file above gets.
	$(INSTALL_DATA) ./files/hysteria-ppp-statuslib $(1)/usr/libexec/hysteria2-ppp-statuslib

	$(INSTALL_DIR) $(1)/usr/libexec/rpcd
	$(INSTALL_BIN) ./files/hysteria-rpcd $(1)/usr/libexec/rpcd/hysteria

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/hysteria-ppp-status $(1)/usr/bin/hysteria-ppp-status
endef

$(eval $(call GoBinPackage,hysteria2-ppp))
$(eval $(call BuildPackage,hysteria2-ppp))
