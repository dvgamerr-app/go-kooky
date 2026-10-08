# go-kooky

Experimental Go library and command-line scaffold for discovering browser profiles and reading
their SQLite cookie stores. Chromium cookie decryption supports the legacy AES-GCM (`v10`/`v11`)
scheme via Windows DPAPI; Firefox profile discovery reads `profiles.ini` directly.

## Supported browser identifiers

- `firefox`
- `opera` (Chromium-based; best effort, `v20` stores report `ErrAppBoundEncryption`)
- `librewolf`, `waterfox`, `zen`, `floorp` (Firefox forks; profile roots follow each project's
  documented default and are unverified against real installs)

Firefox-family browsers do not encrypt `cookies.sqlite` and are the recommended source. Chrome, Edge
and Brave are **not supported** and are rejected with `ErrAppBoundEncryption` (see Current
limitations).

## Library use

```go
cs := browser.NewCookieStore("firefox", profile)
cookies, err := cs.CookiesForHost("act.hoyolab.com") // []*http.Cookie, domain-matched
if errors.Is(err, browser.ErrAppBoundEncryption) {
	// Chromium v20 store: switch to a Firefox-family browser.
}
```

`CookiesForHost` never returns the `[DECRYPT FAILED]` placeholder as a value; it returns the cause
instead. Firefox's `-wal` sidecar is copied with the database so recent cookies are included.

Platform-specific profile locations are resolved under `%LOCALAPPDATA%`/`%APPDATA%` on Windows,
`~/Library/Application Support` on macOS, and `~/.config` or `~/.mozilla/firefox` on Linux.

## Requirements

- Go 1.26 or newer.
- Access to the browser profile of the current OS user.
- Close the target browser before reading cookies if its database is locked.

The project uses the pure-Go `modernc.org/sqlite` driver, so GCC is not required.

## Development commands

Download dependencies and run the standard checks:

```sh
go mod download
go test ./...
go vet ./...
go build ./...
```

The root program is currently an Opera-focused development harness:

```sh
go run .
```

The release CLI prints a per-profile cookie summary (counts only — never a cookie name, domain, or
value) for one or more browsers, which doubles as a quick way to check this library's results
against your own installed browsers:

```sh
go run ./cmd/kooky                    # summarize every supported browser
go run ./cmd/kooky opera               # summarize Opera only
go run ./cmd/kooky firefox opera       # summarize multiple browsers
go run ./cmd/kooky --help
```

## Package layout

- `browser/common.go` — shared cookie model, Local State parsing, and AES-GCM handling.
- `browser/dpapi_windows.go` — Windows-only DPAPI integration.
- `browser/dpapi_other.go` — non-Windows DPAPI capability boundary.
- `browser/cookiestore.go` — profile discovery and SQLite cookie reads.
- `browser/firefox/` — Firefox `profiles.ini` discovery, wired into `cookiestore.go`.
- `cmd/kooky/` — release CLI scaffold.

## Security warning

Browser cookies can grant direct account access. Run this software only against profiles you own or
are explicitly authorized to inspect. Avoid logging or sharing raw cookie values, protect any
exports with restrictive permissions, and delete temporary/output data as soon as it is no longer
needed.

## Current limitations

- **Chrome, Edge, and Brave are not supported.** On current Windows releases those browsers
  have moved cookie encryption to App-Bound Encryption (`v20`), which wraps the AES key behind each
  browser's elevation service (COM) instead of plain DPAPI. This library only implements the legacy
  `v10`/`v11` DPAPI-wrapped-key scheme, so `v20` cookies are reported as `ErrAppBoundEncryption`.
  Confirmed empirically: on a real Windows profile, 100% of sampled Chrome, Edge, and Brave cookies
  were `v20`-prefixed.
- Windows is the only platform with DPAPI support; Chromium key handling on macOS/Linux is not yet
  production-ready.
- Opera's profile/cookie paths follow the same Chromium code path as Chrome/Edge/Brave. Verified
  end-to-end against a synthetic fixture (`browser/opera_integration_test.go`, real Windows DPAPI,
  no real browser data) since no Opera installation was available to test against directly. Whether
  a given Opera release has also moved to `v20`/App-Bound Encryption depends on which Chromium
  milestone that Opera release is based on — not verified either way.
- The CLI prints decrypt-success/failure counts per profile but does not yet export full cookie
  data (names, domains, values) to a file.
- Browser discovery and cookie-schema compatibility need broader automated coverage.
- Cookie databases are copied to a temporary directory before being opened; abnormal termination
  can leave temporary files behind.

## License

MIT
