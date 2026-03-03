package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// camouflage.serverAddr became a list, and the scalar form has to keep working:
// every existing single-address config is written that way, and a config that
// silently stopped parsing would take the server down on upgrade.
//
// Worth pinning rather than assuming, because nothing here spells it out --
// what accepts the scalar is a decode hook viper installs by default, so the
// back-compat rests on a dependency's default and not on this file.
func TestCamouflageServerAddrForms(t *testing.T) {
	decode := func(t *testing.T, yaml string) []string {
		t.Helper()
		v := viper.New()
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(yaml)))
		var c serverConfig
		require.NoError(t, v.Unmarshal(&c))
		return c.Camouflage.ServerAddr
	}

	t.Run("list", func(t *testing.T) {
		assert.Equal(t, []string{"203.0.113.7", "198.51.100.9"},
			decode(t, "camouflage:\n  serverAddr:\n    - 203.0.113.7\n    - 198.51.100.9\n"))
	})
	t.Run("bare scalar", func(t *testing.T) {
		assert.Equal(t, []string{"203.0.113.7"}, decode(t, "camouflage:\n  serverAddr: 203.0.113.7\n"))
	})
	t.Run("comma-separated scalar", func(t *testing.T) {
		assert.Equal(t, []string{"203.0.113.7", "198.51.100.9"},
			decode(t, "camouflage:\n  serverAddr: 203.0.113.7,198.51.100.9\n"))
	})
	t.Run("absent", func(t *testing.T) {
		assert.Empty(t, decode(t, "camouflage:\n  dest: www.bing.com:443\n"))
	})
}
