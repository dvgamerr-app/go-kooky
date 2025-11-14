package kooky_test

import (
	"os"
	"testing"

	"github.com/dvgamerr-app/go-kooky"
	"github.com/dvgamerr-app/go-kooky/browser/chrome"
	"github.com/stretchr/testify/assert"
)

// on macOS:
var cookieStoreMacOs = "/Google/Chrome/Default/Cookies"
var cookieStoreWindows = "\\..\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies"

func TestChromeOnLocal(t *testing.T) {
	// construct file path for the sqlite database containing the cookies
	dir, _ := os.UserConfigDir() // on macOS: "/<USER>/Library/Application Support/"
	var cookieStoreFile string
	if os := os.Getenv("OS"); os == "Darwin" {
		cookieStoreFile = dir + cookieStoreMacOs
	} else {
		cookieStoreFile = dir + cookieStoreWindows
	}

	t.Logf("Cookies: %s", cookieStoreFile)
	cookies, err := chrome.ReadCookies(cookieStoreFile)
	assert.Nilf(t, err, "failed to read cookies: %v")

	for i, cookie := range cookies {
		t.Logf("%+v", cookie)

		if i > 3 {
			break
		}
	}

	cookies = kooky.FilterCookies(cookies, kooky.DomainContains("google"))
	assert.GreaterOrEqual(t, len(cookies), 1)
}
