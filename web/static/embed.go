// Package static contains the page embedded in enigma-web.
package static

import "embed"

// Files is the static site, independent of the process working directory.
//
// Only runtime assets belong here; Node tests and package metadata stay private.
//
//go:embed index.html style.css app.js logic.js i18n/es.json i18n/en.json
var Files embed.FS
