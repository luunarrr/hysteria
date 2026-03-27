# SPDX-License-Identifier: MIT

include $(TOPDIR)/rules.mk

PKG_NAME:=hysteria2-ppp
PKG_VERSION:=0.0.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://codeload.github.com/apernet/hysteria/tar.gz/app/v$(PKG_VERSION)?
PKG_HASH:=7acb5e4ad14146243bf2acbadad141b6167f0ebb678dc6c54a37624284695575
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-app-v$(PKG_VERSION)

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
  TITLE:=A feature-packed proxy tool based on QUIC
  URL:=https://github.com/apernet/hysteria
  DEPENDS:=$(GO_ARCH_DEPENDS) +ca-bundle
endef

define Package/hysteria2-ppp/description
  Hysteria is a feature-packed network utility optimized for networks
  of poor quality powered by a custom version of the QUIC protocol.
endef

define Package/hysteria2-ppp/install
	$(call GoPackage/Package/Install/Bin,$(PKG_INSTALL_DIR))
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/app $(1)/usr/bin/hysteria2-ppp
endef

$(eval $(call GoBinPackage,hysteria2-ppp))
$(eval $(call BuildPackage,hysteria2-ppp))
