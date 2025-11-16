package kooky_test

import (
	"fmt"
	"net/http"
	"regexp"
	"testing"

	"github.com/dvgamerr-app/go-kooky"
)

var reBase64 = regexp.MustCompile(`^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$`)

func TestFilter_regex(t *testing.T) {
	var cookies = []*kooky.Cookie{{Cookie: http.Cookie{Name: `test`, Value: `dGVzdA==`}}}

	cookies = kooky.FilterCookies(
		cookies,
	)

	for _, cookie := range cookies {
		fmt.Println(cookie.Value)
		break // only first element
	}

}

func ValueRegexMatch(re *regexp.Regexp) kooky.Filter {
	return kooky.FilterFunc(func(cookie *kooky.Cookie) bool {
		return cookie != nil && re != nil && re.Match([]byte(cookie.Value))
	})
}
