package recorder

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/textproto"
	"net/url"
	"strings"
	"sync"

	"github.com/apache/thrift/lib/go/thrift"
	"golang.org/x/time/rate"
)

// RateLimiter limit dump rate by http request uri.
type RateLimiter struct {
	lock        sync.RWMutex
	limit       rate.Limit
	burst       int
	limiter     *rate.Limiter
	limiters    map[string]*rate.Limiter
	maxLimiters int
}

// NewRateLimiter create a limiter with default rate limit and burst.
func NewRateLimiter(limit rate.Limit, burst int) *RateLimiter {
	return &RateLimiter{
		limit:       limit,
		burst:       burst,
		limiter:     rate.NewLimiter(limit, burst),
		limiters:    map[string]*rate.Limiter{},
		maxLimiters: 1000,
	}
}

// Set sets limiter for the specified uri.
func (rl *RateLimiter) Set(uri string, limit float64, burst int) {
	rl.lock.Lock()
	defer rl.lock.Unlock()
	rl.limiters[uri] = rate.NewLimiter(rate.Limit(limit), burst)
}

// NotAllow sets the specified uri to disallow.
func (rl *RateLimiter) NotAllow(uri string) {
	rl.lock.Lock()
	defer rl.lock.Unlock()
	rl.limiters[uri] = rate.NewLimiter(0, 0)
}

// Reset resets all limiters.
func (rl *RateLimiter) Reset(limits map[string]float64) {
	limiters := map[string]*rate.Limiter{}
	for k, v := range limits {
		if !rl.check(k, v) {
			continue
		}
		limiters[k] = rate.NewLimiter(rate.Limit(v), rl.burst)
	}

	rl.lock.Lock()
	defer rl.lock.Unlock()
	rl.limiters = limiters
}

func (rl *RateLimiter) check(uri string, limit float64) bool {
	if len(uri) <= 0 || limit < 0 {
		return false
	}
	return true
}

// Allow checks whether the request can be dump
func (rl *RateLimiter) Allow(request []byte, protocol string) (string, bool) {
	uri, ok := parseWithProtocol(request, protocol)
	if !ok {
		return "", rl.limiter.Allow()
	}

	rl.lock.RLock()
	defer rl.lock.RUnlock()
	limiter, ok := rl.limiters[string(uri)]
	if !ok {
		if len(rl.limiters) > rl.maxLimiters {
			return uri, rl.limiter.Allow()
		}
		limiter = rate.NewLimiter(rl.limit, rl.burst)
		rl.limiters[string(uri)] = limiter
	}
	return uri, limiter.Allow()
}

func parseWithProtocol(request []byte, protocol string) (uri string, ok bool) {
	protocols := strings.Split(protocol, ",")
	if len(protocols) == 0 {
		protocols = append(protocols, "http")
	}
	for _, proto := range protocols {
		uri, ok := parseRequestURI(request, proto)
		if ok {
			return uri, ok
		}
	}

	return "", false
}

func parseRequestURI(request []byte, protocol string) (uri string, ok bool) {
	switch protocol {
	case "thrift":
		return parseThriftRequestURI(request)
	case "http":
		return parseHTTPRequestURI(request)
	default:
		return parseHTTPRequestURI(request)
	}
}

func parseThriftRequestURI(request []byte) (uri string, ok bool) {
	reader := thrift.NewTMemoryBuffer()
	reader.Buffer = bytes.NewBuffer(request)
	trans := thrift.NewTHeaderTransport(reader)
	prot := thrift.NewTHeaderProtocol(trans)
	name, _, _, err := prot.ReadMessageBegin(context.TODO())
	if err != nil {
		return "", false
	}

	return name, true
}

func parseHTTPRequestURI(request []byte) (uri string, ok bool) {
	r := bytes.NewReader(request)
	br := bufio.NewReader(io.LimitReader(r, 1024))
	tr := textproto.NewReader(br)
	line, err := tr.ReadLine()
	if err != nil {
		return
	}
	_, reqURI, _, ok := parseHTTPRequestLine(line)
	url, err := url.ParseRequestURI(reqURI)
	if err != nil {
		return
	}
	return url.Path, true
}

func parseHTTPRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}
