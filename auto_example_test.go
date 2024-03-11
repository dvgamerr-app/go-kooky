package kooky_test

import (
	"testing"

	"github.com/dvgamerr-app/go-kooky"
	_ "github.com/dvgamerr-app/go-kooky/browser/all" // This registers all cookiestore finders!
	"github.com/stretchr/testify/assert"
	// _ "github.com/dvgamerr-app/go-kooky/browser/chrome" // load only the chrome cookiestore finder
)

func TestReadCookies_all(t *testing.T) {
	// try to find cookie stores in default locations and
	// read the cookies from them.
	// decryption is handled automatically.
	cookies := kooky.ReadCookies()

	assert.Greater(t, len(cookies), 1)
}

var _ struct{} // ignore this - for correct working of the documentation tool
