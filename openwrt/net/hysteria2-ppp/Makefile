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
  # Either pppd variant will do for a single link. OpenWrt builds the same source
  # twice -- "ppp" with multilink off and "ppp-multilink" with it on -- and the
  # two install the same /usr/sbin/pppd and declare no Conflicts, so depending on
  # one by name would make the other uninstallable alongside this package. This
  # is the form every ppp-mod-* upstream uses for the same reason.
  #
  # Bundling several access concentrators needs the multilink build specifically.
  # The protocol handler asks pppd at setup time and refuses with MLPPP_UNSUPPORTED
  # rather than quietly coming up on one link, so the requirement surfaces where
  # the operator configured it instead of here.
  # The @(...) half is a build-time Kconfig constraint and NOTHING ELSE: package-pack.mk
  # strips @-prefixed entries out of IDEPEND before either the ipk Depends: field
  # or the apk depends: list is emitted. On its own it lets an image select this
  # package =y with ppp only =m, shipping no /usr/sbin/pppd -- at which point
  # hysteria.sh exits at its first line, netifd's one-shot glob never registers
  # the protocol, and it is simply absent from LuCI with nothing logged.
  #
  # The two conditional deps are what put a real runtime dependency on whichever
  # variant was chosen. Depending on "+ppp" by name instead would be wrong the
  # other way: ppp-multilink declares no PROVIDES and no CONFLICTS, installs the
  # same /usr/sbin/pppd, and would be made uninstallable alongside it.
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle @(PACKAGE_ppp||PACKAGE_ppp-multilink) \
	+PACKAGE_ppp:ppp +PACKAGE_ppp-multilink:ppp-multilink
endef

define Package/hysteria2-ppp/description
  Hysteria is a feature-packed network utility optimized for networks
  of poor quality powered by a custom version of the QUIC protocol.

  This build is made from the luunarrr/hysteria master branch, which adds
  PPP over Hysteria2 and camouflage. PPP sessions are established by
  pppd, provided by the ppp package.

  Two ways to run it are installed. The hysteria init script runs it as a
  standalone service configured through /etc/config/hysteria. The netifd
  protocol handler exposes it as an interface protocol, so a hysteria link
  can be declared in /etc/config/network like any other PPP protocol and
  managed with ifup/ifdown, firewall zones and routing metrics.

  The protocol handler can also carry one interface over several access
  concentrators at once, bundling them with Multilink PPP at the LNS. That
  needs a pppd built with multilink, which on OpenWrt is a separate build of
  the same source: install ppp-multilink in place of ppp. The two ship the
  same /usr/sbin/pppd and declare no conflict with each other, so the swap
  has to be made explicitly --

    opkg remove ppp --force-depends && opkg install ppp-multilink

  -- or, when building an image, by selecting ppp-multilink instead of ppp.
endef

define Package/hysteria2-ppp/conffiles
/etc/config/hysteria
endef

# netifd globs /lib/netifd/proto/*.sh exactly once, from proto_shell_init() during
# main(), and never again. A handler dropped into a running system is therefore
# invisible: "ubus call network get_proto_handlers" does not list it, and LuCI
# asks netifd for that list before it loads any protocol JS, so the interface
# protocol is simply absent from the dropdown with nothing logged anywhere.
#
# "reload" does not fix it. netifd_reload() is "return config_init_all()", which
# re-reads /etc/config/network and no more, and that is what /etc/init.d/network
# reload maps onto. Only a restart re-execs netifd and re-globs the directory.
#
# IPKG_INSTROOT is non-empty while the package manager is populating an offline
# rootfs at image build time. Nothing is running to restart then, and netifd's
# first start on the real device already sees the handler.
define Package/hysteria2-ppp/postinst
[ -n "$${IPKG_INSTROOT}" ] && exit 0

# ubus call network restart returns immediately -- netifd takes the interfaces
# down, sets a one second timer and re-execs itself -- so the package manager is
# not left waiting on it. The init script is the fallback for netifd not running.
ubus call network restart 2>/dev/null || /etc/init.d/network restart

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
endef

$(eval $(call GoBinPackage,hysteria2-ppp))
$(eval $(call BuildPackage,hysteria2-ppp))
