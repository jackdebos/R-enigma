// Package static contains the page embedded in enigma-web.
package static

import "embed"

// Files is the static site, independent of the process working directory.
//
//go:embed index.html
var Files embed.FS
