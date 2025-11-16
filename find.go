package kooky

import (
	"net/http"
	"sync"
)

// ...existing code...
type CookieStore interface {
	http.CookieJar
	SubJar(filters ...Filter) (http.CookieJar, error)
	ReadCookies(...Filter) ([]*Cookie, error)
	Browser() string
	Profile() string
	IsDefaultProfile() bool
	FilePath() string
	Close() error
}

// ...existing code...
type CookieStoreFinder interface {
	FindCookieStores() ([]CookieStore, error)
}

var (
	finders  = map[string]CookieStoreFinder{}
	muFinder sync.RWMutex
)

// ...existing code...
func RegisterFinder(browser string, finder CookieStoreFinder) {
	muFinder.Lock()
	defer muFinder.Unlock()
	if finder != nil {
		finders[browser] = finder
	}
}

// ...existing code...
func Finders(browsers ...string) map[string]CookieStoreFinder {
	muFinder.RLock()
	defer muFinder.RUnlock()

	// ...existing code...
	if len(browsers) == 0 {
		result := make(map[string]CookieStoreFinder, len(finders))
		for k, v := range finders {
			result[k] = v
		}
		return result
	}

	// ...existing code...
	result := make(map[string]CookieStoreFinder)
	for _, browser := range browsers {
		if finder, ok := finders[browser]; ok {
			result[browser] = finder
		}
	}
	return result
}

// ...existing code...
// Or only a specific browser:
//
//	import _ "github.com/dvgamerr-app/go-kooky/browser/chrome"
func FindAllCookieStores(browsers ...string) []CookieStore {
	var ret []CookieStore

	muFinder.RLock()
	defer muFinder.RUnlock()

	// Get filtered finders based on browsers parameter
	targetFinders := finders
	if len(browsers) > 0 {
		targetFinders = make(map[string]CookieStoreFinder)
		for _, browser := range browsers {
			if finder, ok := finders[browser]; ok {
				targetFinders[browser] = finder
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(len(targetFinders))

	c := make(chan []CookieStore)
	done := make(chan struct{})

	go func() {
		for cookieStores := range c {
			ret = append(ret, cookieStores...)
		}
		close(done)
	}()

	for _, finder := range targetFinders {
		go func(finder CookieStoreFinder) {
			defer wg.Done()
			cookieStores, err := finder.FindCookieStores()
			if err == nil && cookieStores != nil {
				c <- cookieStores
			}
		}(finder)
	}

	wg.Wait()
	close(c)

	<-done

	return ret
}

// ReadCookies() uses registered cookiestore finders to read cookies.
// Erronous reads are skipped.
//
// Register cookie store finders for all browsers like this:
//
//	import _ "github.com/dvgamerr-app/go-kooky/browser/all"
//
// Or only a specific browser:
//
//	import _ "github.com/dvgamerr-app/go-kooky/browser/chrome"
func ReadCookies(filters ...Filter) []*Cookie {
	var ret []*Cookie

	cs := make(chan []CookieStore)
	c := make(chan []*Cookie)
	done := make(chan struct{})

	// append cookies
	go func() {
		for cookies := range c {
			ret = append(ret, cookies...)
		}
		close(done)
	}()

	// read cookies
	go func() {
		var wgcs sync.WaitGroup
		for cookieStores := range cs {
			for _, store := range cookieStores {
				wgcs.Add(1)
				go func(store CookieStore) {
					defer wgcs.Done()
					cookies, err := store.ReadCookies(filters...)
					if err == nil && cookies != nil {
						c <- cookies
					}
				}(store)
			}

		}
		wgcs.Wait()
		close(c)
	}()

	// find cookie store
	var wgcsf sync.WaitGroup
	muFinder.RLock()
	defer muFinder.RUnlock()
	wgcsf.Add(len(finders))
	for _, finder := range finders {
		go func(finder CookieStoreFinder) {
			defer wgcsf.Done()
			cookieStores, err := finder.FindCookieStores()
			if err == nil && cookieStores != nil {
				cs <- cookieStores
			}
		}(finder)
	}
	wgcsf.Wait()
	close(cs)

	<-done

	return ret
}
