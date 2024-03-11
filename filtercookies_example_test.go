package kooky_test

import (
	"testing"

	"github.com/dvgamerr-app/go-kooky"
	_ "github.com/dvgamerr-app/go-kooky/browser/all" // register cookiestore finders
)

var cookieName = `NID`

func TestFilterCookies(t *testing.T) {
	cookies := kooky.ReadCookies() // automatic read

	kooky.FilterCookies(
		cookies,
		kooky.Valid,                    // remove expired cookies
		kooky.DomainContains(`google`), // cookie domain has to contain "google"
		kooky.Name(cookieName),         // cookie name is "NID"
		kooky.Debug,                    // print cookies after applying previous filter
	)
}
