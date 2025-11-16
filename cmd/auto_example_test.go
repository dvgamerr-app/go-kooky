package kooky_test

import (
	"testing"

	"github.com/dvgamerr-app/go-kooky"
	_ "github.com/dvgamerr-app/go-kooky/browser/all"
	"github.com/stretchr/testify/assert"
)

func TestReadCookies_all(t *testing.T) {
	// ...existing code...
	cookies := kooky.ReadCookies()

	assert.Greater(t, len(cookies), 1)
}
