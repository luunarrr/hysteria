package cmd

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	camo "github.com/apernet/hysteria/extras/v2/camouflage"
	"github.com/apernet/hysteria/extras/v2/transport/udphop"
	"github.com/stretchr/testify/assert"

	"github.com/spf13/viper"
)

// TestClientConfig tests the parsing of the client config
// Addressable so the pointer field in the expected clientConfigCamouflage can
// refer to it; a composite literal cannot take the address of a constant.
var testCamouflageOn = true

func TestClientConfig(t *testing.T) {
	viper.SetConfigFile("client_test.yaml")
	err := viper.ReadInConfig()
	assert.NoError(t, err)
	var config clientConfig
	err = viper.Unmarshal(&config)
	assert.NoError(t, err)
	assertAllFieldsSet(t, config, "client")
	assert.Equal(t, config, clientConfig{
		Server: "example.com",
		Auth:   "weak_ahh_password",
		Realm: clientConfigRealm{
			STUNServers:  []string{"stun1.example.com:3478", "stun2.example.com:3478"},
			STUNTimeout:  6 * time.Second,
			PunchTimeout: 12 * time.Second,
			Insecure:     true,
			IPMode:       "v4",
			PortMapping: realmPortMappingConfig{
				Enabled:  true,
				Timeout:  3 * time.Second,
				Lifetime: 2 * time.Hour,
			},
		},
		Transport: clientConfigTransport{
			Type: "udp",
			UDP: clientConfigTransportUDP{
				HopInterval:    30 * time.Second,
				MinHopInterval: 10 * time.Second,
				MaxHopInterval: 50 * time.Second,
			},
		},
		Obfs: clientConfigObfs{
			Type: "salamander",
			Salamander: clientConfigObfsSalamander{
				Password: "cry_me_a_r1ver",
			},
			Gecko: clientConfigObfsGecko{
				Password:      "g3ck0_in_the_wall",
				MinPacketSize: 100,
				MaxPacketSize: 1200,
			},
		},
		TLS: clientConfigTLS{
			SNI:                "another.example.com",
			Insecure:           true,
			PinSHA256:          "114515DEADBEEF",
			SkipHostnameVerify: true,
			CA:                 "custom_ca.crt",
			ClientCertificate:  "client.crt",
			ClientKey:          "client.key",
			ECH:                "AEv+DQBHAAAgACB3rc0Q",
		},
		QUIC: clientConfigQUIC{
			InitStreamReceiveWindow:     1145141,
			MaxStreamReceiveWindow:      1145142,
			InitConnectionReceiveWindow: 1145143,
			MaxConnectionReceiveWindow:  1145144,
			MaxIdleTimeout:              10 * time.Second,
			KeepAlivePeriod:             4 * time.Second,
			DisablePathMTUDiscovery:     true,
			DisableChromeParrot:         true,
			Sockopts: clientConfigQUICSockopts{
				BindInterface:       stringRef("eth0"),
				FirewallMark:        uint32Ref(1234),
				FdControlUnixSocket: stringRef("test.sock"),
			},
		},
		Mimic: mimicConfig{
			Enabled:   true,
			Interface: "eth0",
			XDPMode:   "skb",
			Path:      "/usr/bin/mimic",
			ExtraArgs: []string{"--padding", "random"},
		},
		Congestion: clientConfigCongestion{
			Type:       "bbr",
			BBRProfile: "aggressive",
		},
		Bandwidth: clientConfigBandwidth{
			Up:                      "200 mbps",
			Down:                    "1 gbps",
			DisableLossCompensation: true,
		},
		FastOpen: true,
		Lazy:     true,
		SOCKS5: &socks5Config{
			Listen:     "127.0.0.1:1080",
			Username:   "anon",
			Password:   "bro",
			DisableUDP: true,
		},
		HTTP: &httpConfig{
			Listen:   "127.0.0.1:8080",
			Username: "qqq",
			Password: "bruh",
			Realm:    "martian",
		},
		TCPForwarding: []tcpForwardingEntry{
			{
				Listen: "127.0.0.1:8088",
				Remote: "internal.example.com:80",
			},
		},
		UDPForwarding: []udpForwardingEntry{
			{
				Listen:  "127.0.0.1:5353",
				Remote:  "internal.example.com:53",
				Timeout: 50 * time.Second,
			},
		},
		TCPTProxy: &tcpTProxyConfig{
			Listen: "127.0.0.1:2500",
		},
		UDPTProxy: &udpTProxyConfig{
			Listen:  "127.0.0.1:2501",
			Timeout: 20 * time.Second,
		},
		TCPRedirect: &tcpRedirectConfig{
			Listen: "127.0.0.1:3500",
		},
		Camouflage: &clientConfigCamouflage{
			Enabled:  &testCamouflageOn,
			Secret:   "c2VjcmV0LWtleS0zMi1ieXRlcy1sb25nLXBhZA==",
			ServerIP: "203.0.113.7",
		},
		TUN: &tunConfig{
			Name:    "hytun",
			MTU:     1500,
			Timeout: 60 * time.Second,
			Address: struct {
				IPv4 string `mapstructure:"ipv4"`
				IPv6 string `mapstructure:"ipv6"`
			}{IPv4: "100.100.100.101/30", IPv6: "2001::ffff:ffff:ffff:fff1/126"},
			Route: &struct {
				Strict      bool     `mapstructure:"strict"`
				IPv4        []string `mapstructure:"ipv4"`
				IPv6        []string `mapstructure:"ipv6"`
				IPv4Exclude []string `mapstructure:"ipv4Exclude"`
				IPv6Exclude []string `mapstructure:"ipv6Exclude"`
			}{
				Strict:      true,
				IPv4:        []string{"0.0.0.0/0"},
				IPv6:        []string{"2000::/3"},
				IPv4Exclude: []string{"192.0.2.1/32"},
				IPv6Exclude: []string{"2001:db8::1/128"},
			},
		},
	})
}

// TestClientConfigURI tests URI-related functions of clientConfig
func TestClientConfigURI(t *testing.T) {
	tests := []struct {
		uri    string
		uriOK  bool
		config *clientConfig
	}{
		{
			uri:   "hysteria2://god@zilla.jp/",
			uriOK: true,
			config: &clientConfig{
				Server: "zilla.jp",
				Auth:   "god",
			},
		},
		{
			uri:   "hysteria2://john:wick@continental.org:4443/",
			uriOK: true,
			config: &clientConfig{
				Server: "continental.org:4443",
				Auth:   "john:wick",
			},
		},
		{
			uri:   "hysteria2://saul@better.call:7000-10000,20000/",
			uriOK: true,
			config: &clientConfig{
				Server: "better.call:7000-10000,20000",
				Auth:   "saul",
			},
		},
		{
			uri:   "hysteria2://noauth.com/?ech=AAj%2BDQAEAAAAAA%3D%3D&insecure=1&obfs=salamander&obfs-password=66ccff&pinSHA256=deadbeef&sni=crap.cc",
			uriOK: true,
			config: &clientConfig{
				Server: "noauth.com",
				Auth:   "",
				Obfs: clientConfigObfs{
					Type: "salamander",
					Salamander: clientConfigObfsSalamander{
						Password: "66ccff",
					},
				},
				TLS: clientConfigTLS{
					SNI:       "crap.cc",
					Insecure:  true,
					PinSHA256: "deadbeef",
					ECH:       "AAj+DQAEAAAAAA==",
				},
			},
		},
		{
			uri:   "hysteria2://pw@geckotown.com:8443/?obfs=gecko&obfs-password=hidden",
			uriOK: true,
			config: &clientConfig{
				Server: "geckotown.com:8443",
				Auth:   "pw",
				Obfs: clientConfigObfs{
					Type: "gecko",
					Gecko: clientConfigObfsGecko{
						Password: "hidden",
					},
				},
			},
		},
		{
			uri:    "invalid.bs",
			uriOK:  false,
			config: nil,
		},
		{
			uri:    "https://www.google.com/search?q=test",
			uriOK:  false,
			config: nil,
		},
	}
	for _, test := range tests {
		t.Run(test.uri, func(t *testing.T) {
			// Test parseURI
			nc := &clientConfig{Server: test.uri}
			assert.Equal(t, nc.parseURI(), test.uriOK)
			if test.uriOK {
				assert.Equal(t, nc, test.config)
			}
			// Test URI generation
			if test.config != nil {
				assert.Equal(t, test.config.URI(), test.uri)
			}
		})
	}
}

func TestClientConfigParseRealmAddr(t *testing.T) {
	c := &clientConfig{Server: "realm+http://token@example.com/realm?stun=stun1.example.com:3478&stun=stun2.example.com:3478"}
	addr, ok, err := c.parseRealmAddr()
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "http", addr.RendezvousScheme)
	assert.Equal(t, "token", addr.Token)
	assert.Equal(t, "realm", addr.RealmID)
	assert.Equal(t, []string{"stun1.example.com:3478", "stun2.example.com:3478"}, c.realmSTUNServers(addr))
}

func TestClientConfigRealmSTUNServers(t *testing.T) {
	addr, ok, err := (&clientConfig{Server: "realm://token@example.com/realm"}).parseRealmAddr()
	assert.NoError(t, err)
	assert.True(t, ok)

	c := &clientConfig{}
	assert.Equal(t, defaultRealmSTUNServers, c.realmSTUNServers(addr))

	c.Realm.STUNServers = []string{"custom.example.com:3478"}
	assert.Equal(t, []string{"custom.example.com:3478"}, c.realmSTUNServers(addr))
}

func TestClientConfigParseInvalidRealmAddr(t *testing.T) {
	_, ok, err := (&clientConfig{Server: "realm://example.com/realm"}).parseRealmAddr()
	assert.True(t, ok)
	assert.Error(t, err)
}

func TestSingleUseConnFactory(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	assert.NoError(t, err)
	defer conn.Close()

	f := &singleUseConnFactory{Open: func() (net.PacketConn, error) { return conn, nil }}
	got, err := f.New(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	assert.NoError(t, err)
	assert.Equal(t, conn, got)

	_, err = f.New(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	assert.Error(t, err)
}

func TestParseAddrPorts(t *testing.T) {
	addrs, err := parseAddrPorts([]string{"198.51.100.20:4433", "[2001:db8::1]:4433"})
	assert.NoError(t, err)
	assert.Equal(t, []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.20:4433"),
		netip.MustParseAddrPort("[2001:db8::1]:4433"),
	}, addrs)

	_, err = parseAddrPorts([]string{"not-an-address"})
	assert.Error(t, err)
}

func TestClientFillCongestionConfig(t *testing.T) {
	t.Run("defaults to bbr standard", func(t *testing.T) {
		hyConfig := &client.Config{}
		err := (&clientConfig{}).fillCongestionConfig(hyConfig)
		assert.NoError(t, err)
		assert.Equal(t, "bbr", hyConfig.CongestionConfig.Type)
		assert.Equal(t, "standard", hyConfig.CongestionConfig.BBRProfile)
	})

	t.Run("reno ignores bbr profile", func(t *testing.T) {
		hyConfig := &client.Config{}
		err := (&clientConfig{
			Congestion: clientConfigCongestion{
				Type:       "reno",
				BBRProfile: "definitely-invalid",
			},
		}).fillCongestionConfig(hyConfig)
		assert.NoError(t, err)
		assert.Equal(t, "reno", hyConfig.CongestionConfig.Type)
		assert.Empty(t, hyConfig.CongestionConfig.BBRProfile)
	})

	t.Run("rejects invalid type", func(t *testing.T) {
		err := (&clientConfig{
			Congestion: clientConfigCongestion{Type: "cubic"},
		}).fillCongestionConfig(&client.Config{})
		assert.EqualError(t, err, `invalid config: congestion.type: unsupported congestion type "cubic"`)
	})

	t.Run("rejects invalid bbr profile", func(t *testing.T) {
		err := (&clientConfig{
			Congestion: clientConfigCongestion{
				Type:       "bbr",
				BBRProfile: "turbo",
			},
		}).fillCongestionConfig(&client.Config{})
		assert.EqualError(t, err, `invalid config: congestion.bbrProfile: unsupported BBR profile "turbo"`)
	})
}

func TestClientTransportUDPHopIntervalConfig(t *testing.T) {
	t.Run("fixed interval", func(t *testing.T) {
		cfg, err := (clientConfigTransportUDP{HopInterval: 30 * time.Second}).hopIntervalConfig()
		assert.NoError(t, err)
		assert.Equal(t, 30*time.Second, cfg.Min)
		assert.Equal(t, 30*time.Second, cfg.Max)
	})

	t.Run("range interval", func(t *testing.T) {
		cfg, err := (clientConfigTransportUDP{
			MinHopInterval: 10 * time.Second,
			MaxHopInterval: 30 * time.Second,
		}).hopIntervalConfig()
		assert.NoError(t, err)
		assert.Equal(t, 10*time.Second, cfg.Min)
		assert.Equal(t, 30*time.Second, cfg.Max)
	})

	t.Run("default interval", func(t *testing.T) {
		cfg, err := (clientConfigTransportUDP{}).hopIntervalConfig()
		assert.NoError(t, err)
		assert.Zero(t, cfg.Min)
		assert.Zero(t, cfg.Max)
	})

	t.Run("rejects mixed fields", func(t *testing.T) {
		_, err := (clientConfigTransportUDP{
			HopInterval:    30 * time.Second,
			MinHopInterval: 10 * time.Second,
			MaxHopInterval: 30 * time.Second,
		}).hopIntervalConfig()
		assert.EqualError(t, err, "hopInterval cannot be used together with minHopInterval or maxHopInterval")
	})

	t.Run("rejects partial range", func(t *testing.T) {
		_, err := (clientConfigTransportUDP{
			MinHopInterval: 10 * time.Second,
		}).hopIntervalConfig()
		assert.EqualError(t, err, "minHopInterval and maxHopInterval must both be set")
	})
}

func stringRef(s string) *string {
	return &s
}

func uint32Ref(i uint32) *uint32 {
	return &i
}

// TestClientFillCamouflage covers deriving the client PSK from the auth string
// it is already configured with, and the end-to-end agreement with what a
// server derives for the same account.
func TestClientFillCamouflage(t *testing.T) {
	const serverIP = "203.0.113.7"
	udpAddr := func(ip string) net.Addr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 443} }
	enabled := true
	disabled := false

	fill := func(t *testing.T, config clientConfig, addr net.Addr) (*client.Config, error) {
		t.Helper()
		hyConfig := &client.Config{ServerAddr: addr}
		return hyConfig, config.fillCamouflage(hyConfig)
	}

	t.Run("absent block is a no-op", func(t *testing.T) {
		hyConfig, err := fill(t, clientConfig{Auth: "bear:hunter2"}, udpAddr(serverIP))
		assert.NoError(t, err)
		assert.Nil(t, hyConfig.QUICConfig.InitialDestConnectionID)
	})

	t.Run("enabled false is a no-op", func(t *testing.T) {
		hyConfig, err := fill(t, clientConfig{
			Auth:       "bear:hunter2",
			Camouflage: &clientConfigCamouflage{Enabled: &disabled, ServerIP: serverIP},
		}, udpAddr(serverIP))
		assert.NoError(t, err)
		assert.Nil(t, hyConfig.QUICConfig.InitialDestConnectionID)
	})

	// The property multilink depends on: nothing in the config names a
	// concentrator, so one shared configuration produces a different, correct
	// token per link purely from the address that link dials.
	t.Run("address derived per link", func(t *testing.T) {
		shared := clientConfig{
			Auth:       "bear:hunter2",
			Camouflage: &clientConfigCamouflage{Enabled: &enabled},
		}
		secrets := map[string][]byte{"bear": camo.DerivePSK("bear:hunter2")}

		for _, ip := range []string{"203.0.113.7", "198.51.100.9"} {
			hyConfig, err := fill(t, shared, udpAddr(ip))
			assert.NoError(t, err)
			dcid := hyConfig.QUICConfig.InitialDestConnectionID

			res := camo.VerifyDCID(secrets, net.ParseIP(ip), dcid, 0)
			assert.True(t, res.Matched(), "own concentrator must accept: %s", ip)
			assert.True(t, res.ServerIDMatch, "own concentrator must match server_id: %s", ip)
			assert.Equal(t, "bear", res.Label)

			// And the same token must not pass as another concentrator's, which
			// is the cross-server replay protection the address exists for.
			other := camo.VerifyDCID(secrets, net.ParseIP("192.0.2.1"), dcid, 0)
			assert.True(t, other.Matched())
			assert.False(t, other.ServerIDMatch, "token must not match a different concentrator")
		}
	})

	t.Run("port hopping address derives too", func(t *testing.T) {
		hopAddr := &udphop.UDPHopAddr{IP: net.ParseIP(serverIP), Ports: []uint16{443}, PortStr: "443"}
		hyConfig, err := fill(t, clientConfig{
			Auth:       "bear:hunter2",
			Camouflage: &clientConfigCamouflage{Enabled: &enabled},
		}, hopAddr)
		assert.NoError(t, err)
		res := camo.VerifyDCID(map[string][]byte{"bear": camo.DerivePSK("bear:hunter2")},
			net.ParseIP(serverIP), hyConfig.QUICConfig.InitialDestConnectionID, 0)
		assert.True(t, res.Matched())
		assert.True(t, res.ServerIDMatch)
	})

	t.Run("explicit serverIP overrides the dialed address", func(t *testing.T) {
		hyConfig, err := fill(t, clientConfig{
			Auth:       "bear:hunter2",
			Camouflage: &clientConfigCamouflage{Enabled: &enabled, ServerIP: "192.0.2.1"},
		}, udpAddr(serverIP))
		assert.NoError(t, err)
		secrets := map[string][]byte{"bear": camo.DerivePSK("bear:hunter2")}
		dcid := hyConfig.QUICConfig.InitialDestConnectionID
		assert.True(t, camo.VerifyDCID(secrets, net.ParseIP("192.0.2.1"), dcid, 0).ServerIDMatch)
		assert.False(t, camo.VerifyDCID(secrets, net.ParseIP(serverIP), dcid, 0).ServerIDMatch)
	})

	t.Run("invalid explicit serverIP is rejected", func(t *testing.T) {
		_, err := fill(t, clientConfig{
			Auth:       "bear:hunter2",
			Camouflage: &clientConfigCamouflage{Enabled: &enabled, ServerIP: "not-an-ip"},
		}, udpAddr(serverIP))
		assert.ErrorContains(t, err, "camouflage.serverIP")
	})

	t.Run("underivable address asks for an explicit one", func(t *testing.T) {
		_, err := fill(t, clientConfig{
			Server:     "somewhere:443",
			Auth:       "bear:hunter2",
			Camouflage: &clientConfigCamouflage{Enabled: &enabled},
		}, nil)
		assert.ErrorContains(t, err, "cannot be derived from server address")
	})

	t.Run("explicit secret wins over derivation", func(t *testing.T) {
		hyConfig, err := fill(t, clientConfig{
			Auth: "bear:hunter2",
			Camouflage: &clientConfigCamouflage{
				Enabled: &enabled,
				Secret:  "c2VjcmV0LWtleS0zMi1ieXRlcy1sb25nLXBhZA==",
			},
		}, udpAddr(serverIP))
		assert.NoError(t, err)
		derived := map[string][]byte{"bear": camo.DerivePSK("bear:hunter2")}
		assert.False(t, camo.VerifyDCID(derived, net.ParseIP(serverIP),
			hyConfig.QUICConfig.InitialDestConnectionID, 0).Matched())
	})

	t.Run("invalid secret is rejected", func(t *testing.T) {
		_, err := fill(t, clientConfig{
			Camouflage: &clientConfigCamouflage{Enabled: &enabled, Secret: "not!base64"},
		}, udpAddr(serverIP))
		assert.ErrorContains(t, err, "camouflage.secret")
	})

	t.Run("empty auth leaves nothing to derive from", func(t *testing.T) {
		_, err := fill(t, clientConfig{
			Camouflage: &clientConfigCamouflage{Enabled: &enabled},
		}, udpAddr(serverIP))
		assert.ErrorContains(t, err, "camouflage.secret")
	})

	t.Run("password auth agrees end to end", func(t *testing.T) {
		hyConfig, err := fill(t, clientConfig{
			Auth:       "hunter2",
			Camouflage: &clientConfigCamouflage{Enabled: &enabled},
		}, udpAddr(serverIP))
		assert.NoError(t, err)
		res := camo.VerifyDCID(map[string][]byte{"password": camo.DerivePSK("hunter2")},
			net.ParseIP(serverIP), hyConfig.QUICConfig.InitialDestConnectionID, 0)
		assert.True(t, res.Matched())
		assert.Equal(t, "password", res.Label)
	})
}
