package logging_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/samuel-stidham/safetybox/internal/logging"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLevelFiltering(t *testing.T) {
	tests := []struct {
		name       string
		opts       logging.Options
		logAt      slog.Level
		wantLogged bool
	}{
		{name: "debug suppressed by default", opts: logging.Options{}, logAt: slog.LevelDebug, wantLogged: false},
		{name: "info suppressed by default", opts: logging.Options{}, logAt: slog.LevelInfo, wantLogged: false},
		{name: "warn logged by default", opts: logging.Options{}, logAt: slog.LevelWarn, wantLogged: true},
		{name: "error logged by default", opts: logging.Options{}, logAt: slog.LevelError, wantLogged: true},
		{name: "debug logged when verbose", opts: logging.Options{Verbose: true}, logAt: slog.LevelDebug, wantLogged: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			logger := logging.New(&buf, tt.opts)
			logger.Log(t.Context(), tt.logAt, "probe message")

			if tt.wantLogged {
				assert.Contains(t, buf.String(), "probe message")
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestTextFormatByDefault(t *testing.T) {
	var buf bytes.Buffer

	logging.New(&buf, logging.Options{}).Warn("probe message", "verb", "list")

	assert.Contains(t, buf.String(), "msg=\"probe message\"")
	assert.Contains(t, buf.String(), "verb=list")
}

func TestJSONFormat(t *testing.T) {
	var buf bytes.Buffer

	logging.New(&buf, logging.Options{JSON: true}).Warn("probe message", "verb", "list")

	var record map[string]any

	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
	assert.Equal(t, "probe message", record["msg"])
	assert.Equal(t, "list", record["verb"])
}

func TestSetupInstallsDefault(t *testing.T) {
	previous := slog.Default()

	t.Cleanup(func() { slog.SetDefault(previous) })

	logger := logging.Setup(logging.Options{})

	assert.Same(t, logger, slog.Default())
}
