package recorder

import (
	"os"

	"github.com/didi/yarc/internal/log"
	"github.com/didi/yarc/pkg/model"

	"github.com/rs/zerolog"
)

// SessionWriter writes sessions to store.
type SessionWriter interface {
	Write(s *model.Session)
}

type LogWriter struct {
	logger zerolog.Logger
}

type LogWriterConfig struct {
	LogDir     string
	LogFile    string
	AutoClear  bool
	ClearHours int
}

// OpType for kafka -> es
type OpType int

const (
	OpIndex OpType = 100001
)

func DefaultSessionWriter() SessionWriter {
	cfg := LogWriterConfig{
		LogDir:     "./log/",
		LogFile:    "record.log",
		AutoClear:  true,
		ClearHours: 4,
	}
	return NewLogWriter(&cfg)
}

func NewLogWriter(cfg *LogWriterConfig) *LogWriter {
	err := os.MkdirAll(cfg.LogDir, 0755)
	if err != nil {
		panic(err)
	}

	clearHours := 0
	if cfg.AutoClear {
		clearHours = cfg.ClearHours
	}

	file := log.NewRotateFileWriter(cfg.LogDir, cfg.LogFile, clearHours)
	return &LogWriter{
		logger: zerolog.New(file),
	}
}

func (w *LogWriter) Write(s *model.Session) {
	data, _ := s.MarshalJSON()
	w.logger.Log().Int("operate", int(OpIndex)).RawJSON("data", data).Msg("")
}
