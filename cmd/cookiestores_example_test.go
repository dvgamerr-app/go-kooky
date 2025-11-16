package kooky_test

import (
	"fmt"
	"testing"

	"github.com/dvgamerr-app/go-kooky"
	_ "github.com/dvgamerr-app/go-kooky/browser/all"
)

func TestFindAllCookieStores(t *testing.T) {
	cookieStores := kooky.FindAllCookieStores()

	for _, store := range cookieStores {
		// ...existing code...
		defer store.Close()

		var filters = []kooky.Filter{
			kooky.Valid, // remove expired cookies
		}

		cookies, _ := store.ReadCookies(filters...)
		for _, cookie := range cookies {
			fmt.Printf(
				"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				store.Browser(),
				store.Profile(),
				store.FilePath(),
				cookie.Domain,
				cookie.Name,
				cookie.Value,
				cookie.Expires.Format(`2006.01.02 15:04:05`),
			)
		}
	}
}
