package recorder

import (
	"sync"
	"time"
)

// Option sets option for recorder
type Option func(opts *Options)
type NewRecorderFunc func(*Options, *sync.Pool) RecorderIntf

// Options saves options for recorder
type Options struct {
	GoVersion      int
	ServiceName    string
	ClusterName    string
	Hostname       string
	MinEventCount  int
	SessionBufSize int
	EventBufSize   int
	RateLimit      float64
	BlackList      []string
	MaxActions     int
	SessionExpire  time.Duration
	ThreadExpire   time.Duration
	SocketExpire   time.Duration
	MaxLogDataLen  int
	SessionWriter  SessionWriter
	NewRecorder    NewRecorderFunc
	Protocol       string
	EnableTrace    bool
}

// NewDefaultOptions create a default options.
func NewDefaultOptions() *Options {
	return &Options{
		ServiceName:    "unknown",
		ClusterName:    "unknown",
		Hostname:       "unknown",
		MinEventCount:  10240,
		SessionBufSize: 10240,
		EventBufSize:   40960,
		RateLimit:      0.1,
		MaxActions:     1000,
		SessionExpire:  20 * time.Second,
		ThreadExpire:   60 * time.Second,
		SocketExpire:   60 * time.Second,
		MaxLogDataLen:  200,
		SessionWriter:  DefaultSessionWriter(),
		NewRecorder:    NewSessionRecorder,
	}
}

// WithGoVersion sets go version
func WithGoVersion(ver int) Option {
	return func(opts *Options) {
		opts.GoVersion = ver
	}
}

// WithServiceName sets ServiceName
func WithServiceName(service string) Option {
	return func(opts *Options) {
		opts.ServiceName = service
	}
}

// WithClusterName sets ClusterName
func WithClusterName(cluster string) Option {
	return func(opts *Options) {
		opts.ClusterName = cluster
	}
}

// WithHostname sets hostname
func WithHostname(hostname string) Option {
	return func(opts *Options) {
		opts.Hostname = hostname
	}
}

// WithMinEventCount sets MinEventCount
func WithMinEventCount(count int) Option {
	return func(opts *Options) {
		opts.MinEventCount = count
	}
}

// WithSessionBufSize sets SessionBufSize
func WithSessionBufSize(size int) Option {
	return func(opts *Options) {
		opts.SessionBufSize = size
	}
}

// WithEventBufSize sets EventBufSize
func WithEventBufSize(size int) Option {
	return func(opts *Options) {
		opts.EventBufSize = size
	}
}

// WithBlackList sets BlackList
func WithBlackList(list []string) Option {
	return func(opts *Options) {
		opts.BlackList = list
	}
}

// WithRateLimit sets RateLimit
func WithRateLimit(limit float64) Option {
	return func(opts *Options) {
		opts.RateLimit = limit
	}
}

// WithMaxActions sets MaxActions
func WithMaxActions(max int) Option {
	return func(opts *Options) {
		opts.MaxActions = max
	}
}

// WithSessionExpire sets SessionExpire
func WithSessionExpire(expire time.Duration) Option {
	return func(opts *Options) {
		opts.SessionExpire = expire
	}
}

// WithThreadExpire sets ThreadExpire
func WithThreadExpire(expire time.Duration) Option {
	return func(opts *Options) {
		opts.ThreadExpire = expire
	}
}

// WithSocketExpire sets SocketExpire
func WithSocketExpire(expire time.Duration) Option {
	return func(opts *Options) {
		opts.SocketExpire = expire
	}
}

// WithMaxLogDataLen sets MaxLogDataLen
func WithMaxLogDataLen(max int) Option {
	return func(opts *Options) {
		opts.MaxLogDataLen = max
	}
}

// WithSessionWriter sets SessionWriter
func WithSessionWriter(writer SessionWriter) Option {
	return func(opts *Options) {
		opts.SessionWriter = writer
	}
}

// WithNewRecorder sets NewRecorder
func WithNewRecorder(f NewRecorderFunc) Option {
	return func(opts *Options) {
		opts.NewRecorder = f
	}
}
