package recorder

import "testing"

func TestRateLimit(t *testing.T) {
	tests := []struct {
		Request string
		Allow   bool
	}{
		{"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", true},
		{"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", true},
		{"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", false},
		{"GET /foo/bar HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", true},
		{"GET /foo/bar?a=1 HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", true},
		{"GET /foo/bar?b=2 HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n", true},
	}

	limiter := NewRateLimiter(0.1, 2)
	for _, test := range tests {
		_, allow := limiter.Allow([]byte(test.Request))
		if allow != test.Allow {
			t.Log("request: ", test.Request, "actual:", allow, "expect:", test.Allow)
			t.Fail()
		}
	}
	t.Log(limiter.limiters)
}
