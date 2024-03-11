package kooky_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dvgamerr-app/go-kooky"
	_ "github.com/dvgamerr-app/go-kooky/browser/chrome"
)

func TestCookieJar(t *testing.T) {
	stores := kooky.FindAllCookieStores()
	for _, store := range stores {
		if store.Browser() != `chrome` {
			continue
		}
		jar, _ := store.SubJar(kooky.Domain(`github.com`))
		if jar == nil {
			continue
		}

		u, _ := url.Parse(`https://github.com/settings/profile`)
		var loggedIn bool

		cookies := kooky.FilterCookies(jar.Cookies(u), kooky.Name(`logged_in`))
		if len(cookies) > 0 {
			loggedIn = true
		}
		if !loggedIn {
			log.Fatal(`not logged in`)
		}

		client := http.Client{Jar: jar}
		resp, _ := client.Get(u.String())
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), `id="user_profile_name"`) {
			fmt.Print("not ")
		}
		fmt.Println("logged in")
		break
	}

	// Output: logged in
}
