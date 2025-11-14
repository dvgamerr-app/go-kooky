package kooky

import (
	"encoding/base64"
	"net/http"
	"time"
)

// TODO(zellyn): figure out what to do with quoted values, like the "bcookie" cookie
// from slideshare.net

// Cookie is the struct returned by functions in this package. Similar to http.Cookie.
type Cookie struct {
	http.Cookie
	Creation  time.Time
	Container string
}

// SafeValue returns the cookie value encoded as ASCII-safe string using Base64 URL encoding
// if it contains invalid bytes (control characters or non-ASCII), otherwise returns the original value.
// This is useful when setting the cookie in net/http.Cookie.Value to avoid "invalid byte" errors.
func (c *Cookie) SafeValue() string {
	return safeCookieValue(c.Value)
}

// String returns a string representation of the cookie, using SafeValue for the Value field
// to avoid "invalid byte" errors from net/http validation.
func (c *Cookie) String() string {
	// Create a copy of the cookie with safe value
	safeCookie := c.Cookie
	safeCookie.Value = c.SafeValue()
	return safeCookie.String()
}

// safeCookieValue checks if the raw string contains only ASCII-safe characters.
// If not, it encodes it with Base64 URL encoding.
func safeCookieValue(raw string) string {
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b <= 0x20 || b >= 0x7f { // control or non-ASCII
			return base64.RawURLEncoding.EncodeToString([]byte(raw))
		}
	}
	return raw
}
