package kooky_test

import (
	"testing"

	"github.com/dvgamerr-app/go-kooky"
	_ "github.com/dvgamerr-app/go-kooky/browser/all"
	"github.com/stretchr/testify/assert"
)

func TestOnLocal(t *testing.T) {

	cookies := kooky.ReadCookies(kooky.DomainContains("google"))
	cookies = kooky.FilterCookies(cookies, kooky.DomainContains("google"))

	for _, c := range cookies {
		t.Logf("Key: %s, Value: %s", c.Name, c.Value)
	}

	assert.GreaterOrEqual(t, len(cookies), 1)
}

func TestFilterByBrowserAndDomain(t *testing.T) {
	stores := kooky.FindAllCookieStores()
	var cookies []*kooky.Cookie
	for _, store := range stores {
		storeCookies, err := store.ReadCookies(kooky.DomainContains("google.com"))
		if err == nil {
			cookies = append(cookies, storeCookies...)
		}
	}
	assert.GreaterOrEqual(t, len(cookies), 1)
	for _, c := range cookies {
		t.Logf("Key: %s, Value: %q", c.Name, c.Value)
	}
}
