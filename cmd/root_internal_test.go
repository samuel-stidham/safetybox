package cmd

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	envVaultValue    = "/from/env/vault.db"
	envIdentityValue = "/from/env/identity.age"
	xdgBase          = "/from/xdg"
)

func TestResolveVaultPathPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		flag     string
		env      string
		xdgData  string
		wantPath func(home string) string
	}{
		{
			name: "flag wins over env and xdg",
			flag: "/from/flag/vault.db",
			env:  envVaultValue, xdgData: xdgBase,
			wantPath: func(string) string { return "/from/flag/vault.db" },
		},
		{
			name: "env wins over xdg",
			env:  envVaultValue, xdgData: xdgBase,
			wantPath: func(string) string { return envVaultValue },
		},
		{
			name:    "xdg data home",
			xdgData: xdgBase,
			wantPath: func(string) string {
				return filepath.Join(xdgBase, "safetybox", "vault.db")
			},
		},
		{
			name: "home fallback",
			wantPath: func(home string) string {
				return filepath.Join(home, ".local", "share", "safetybox", "vault.db")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv(envVault, tt.env)
			t.Setenv("XDG_DATA_HOME", tt.xdgData)

			opts := &options{vaultPath: tt.flag}

			got, err := opts.resolveVaultPath()
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath(home), got)
		})
	}
}

func TestResolveIdentityPathPrecedence(t *testing.T) {
	tests := []struct {
		name      string
		flag      string
		env       string
		xdgConfig string
		wantPath  func(home string) string
	}{
		{
			name: "flag wins over env and xdg",
			flag: "/from/flag/identity.age",
			env:  envIdentityValue, xdgConfig: xdgBase,
			wantPath: func(string) string { return "/from/flag/identity.age" },
		},
		{
			name: "env wins over xdg",
			env:  envIdentityValue, xdgConfig: xdgBase,
			wantPath: func(string) string { return envIdentityValue },
		},
		{
			name:      "xdg config home",
			xdgConfig: xdgBase,
			wantPath: func(string) string {
				return filepath.Join(xdgBase, "safetybox", "identity.age")
			},
		},
		{
			name: "home fallback",
			wantPath: func(home string) string {
				return filepath.Join(home, ".config", "safetybox", "identity.age")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv(envIdentity, tt.env)
			t.Setenv("XDG_CONFIG_HOME", tt.xdgConfig)

			opts := &options{identityPath: tt.flag}

			got, err := opts.resolveIdentityPath()
			require.NoError(t, err)
			assert.Equal(t, tt.wantPath(home), got)
		})
	}
}

func TestVersionIsWiredToCobra(t *testing.T) {
	root := newRootCmd("1.2.3-test")
	root.SetArgs([]string{"--version"})

	var out bytes.Buffer

	root.SetOut(&out)
	root.SetErr(io.Discard)

	require.NoError(t, root.Execute())
	assert.Equal(t, "safetybox version 1.2.3-test\n", out.String())
	assert.NotContains(t, out.String(), "\x1b")
}

// TestLogJSONRequested pins the pre-parse --log-json scan. The early
// logger installs before flags are parsed, so this decision is what
// keeps a requested JSON stream JSON when the parse itself fails. The
// exec cases guard the interspersion rule: everything from the child
// command onward belongs to the child, so a child --log-json must
// never switch safetybox's own logs.
func TestLogJSONRequested(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "no args", args: nil, want: false},
		{name: "plain verb", args: []string{"list"}, want: false},
		{name: "before a bad flag", args: []string{"--log-json", "--bogusflag"}, want: true},
		{name: "after a bad flag", args: []string{"--bogusflag", "--log-json", "list"}, want: true},
		{name: "explicit true before a bad flag", args: []string{"--log-json=true", "--bogusflag"}, want: true},
		{name: "explicit false", args: []string{"--log-json=false", "list"}, want: false},
		{name: "after the verb", args: []string{"list", "--log-json", "--bogusflag"}, want: true},
		{name: "before an unknown verb", args: []string{"--log-json", "bogusverb"}, want: true},
		{name: "before the exec verb", args: []string{"--log-json", "exec", "app"}, want: true},
		{name: "exec own flag region", args: []string{"exec", "--log-json", "app"}, want: true},
		{name: "exec child arg without separator", args: []string{"exec", "app", "--log-json"}, want: false},
		{name: "exec child arg behind the separator", args: []string{"exec", "--", "app", "--log-json"}, want: false},
		{name: "consumed as a string flag's value", args: []string{"--passphrase-file", "--log-json", "list"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, logJSONRequested("test", tt.args))
		})
	}
}

func TestZeroBytes(t *testing.T) {
	buf := []byte{1, 2, 3}

	zeroBytes(buf)

	assert.Equal(t, []byte{0, 0, 0}, buf)
}
