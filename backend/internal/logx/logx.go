// Package logx 只是把 slog 的构造收在一处，避免各包重复判断格式。
package logx

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/EnderCraft-Server/vote-system/backend/internal/config"
)

func New(cfg config.Log) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return NewWith(os.Stdout, lvl, cfg.Format)
}

func NewWith(w io.Writer, lvl slog.Level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h)
}
