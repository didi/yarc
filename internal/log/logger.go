package log

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
)

type Config struct {
	LogDir     string
	LogPrefix  string
	LogLevel   string
	AutoClear  bool
	ClearHours int
}

var logger *zerolog.Logger

// InitLogger init logger
func InitLogger(config *Config) {
	if config.LogPrefix == "" {
		panic("log.file_prefix can not be empty")
	}

	logDir := config.LogDir
	logDir, err := filepath.Abs(logDir)
	if err != nil {
		panic(err)
	}

	err = os.MkdirAll(logDir, 0775)
	if err != nil {
		panic(err)
	}

	writer := zerolog.MultiLevelWriter(NewRotateFileWriter(logDir, "yarc.log", config.ClearHours),
		NewRotateFileWriter(logDir, "yarc.log.wf", config.ClearHours))
	tmpLogger := zerolog.New(writer)

	lev := strings.ToLower(config.LogLevel)
	l, err := zerolog.ParseLevel(lev)
	if err != nil || lev == "" {
		l = zerolog.DebugLevel
	}
	tmpLogger = tmpLogger.Level(l)

	logger = &tmpLogger
}

func G() *zerolog.Logger {
	return logger
}

func Fatal() *zerolog.Event {
	return logger.Fatal().Timestamp().Caller()
}

func Error() *zerolog.Event {
	return logger.Error().Timestamp().Caller()
}

func Warn() *zerolog.Event {
	return logger.Warn().Timestamp().Caller()
}

func Info() *zerolog.Event {
	return logger.Info().Timestamp().Caller()
}

func Debug() *zerolog.Event {
	return logger.Debug().Timestamp().Caller()
}
