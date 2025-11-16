package netscape

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/dvgamerr-app/go-kooky"
)

const httpOnlyPrefix = `#HttpOnly_`

func (s *CookieStore) ReadCookies(filters ...kooky.Filter) ([]*kooky.Cookie, error) {
	if s == nil {
		return nil, errors.New(`cookie store is nil`)
	}
	if err := s.Open(); err != nil {
		return nil, err
	} else if s.File == nil {
		return nil, errors.New(`file is nil`)
	}

	cookies, isStrict, err := ReadCookies(s.File, filters...)
	s.IsStrictBool = isStrict

	return cookies, err
}

func ReadCookies(file io.Reader, filters ...kooky.Filter) (c []*kooky.Cookie, strict bool, e error) {

	if file == nil {
		return nil, false, errors.New(`file is nil`)
	}

	var ret []*kooky.Cookie

	var lineNr uint
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if lineNr == 0 && (line == `# HTTP Cookie File` || line == `# Netscape HTTP Cookie File`) {
			strict = true
		}
		// split line into fields
		sp := strings.Split(line, "\t")
		if len(sp) != 7 {
			continue
		}
		var exp int64
		if len(sp[4]) > 0 {
			e, err := strconv.ParseInt(sp[4], 10, 64)
			if err != nil {
				continue
			} else {
				exp = e
			}
		} else {
			strict = false
		}

		cookie := &kooky.Cookie{}
		switch sp[3] {
		case `TRUE`:
			cookie.Secure = true
		case `FALSE`:
		default:
			continue
		}

		if strings.HasPrefix(sp[0], httpOnlyPrefix) {
			cookie.Domain = sp[0][len(httpOnlyPrefix):]
			cookie.HttpOnly = true
		} else {
			cookie.Domain = sp[0]
		}

		cookie.Path = sp[2]
		cookie.Name = sp[5]
		cookie.Value = strings.TrimSpace(sp[6])
		cookie.Expires = time.Unix(exp, 0)

		if !kooky.FilterCookie(cookie, filters...) {
			continue
		}

		ret = append(ret, cookie)
	}

	return ret, strict, nil
}
