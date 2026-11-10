package netcode

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestDocumentedVersionAndUpdateTime(t *testing.T) {
	claude, err := os.ReadFile("CLAUDE.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(claude)
	quoted := "`VersionFull` \"" + VersionFull + "\""
	if !strings.Contains(text, quoted) {
		t.Errorf("CLAUDE.md does not document %s", quoted)
	}
	if strings.Contains(text, "v1.0.0 -> v1.1.0") {
		t.Errorf("CLAUDE.md still describes the module line as v1.0.0 -> v1.1.0")
	}
	// the module line is its own numbering, so any release may close it
	if !regexp.MustCompile(`v1\.0\.0 -> v[0-9]+\.[0-9]+\.[0-9]+`).MatchString(text) {
		t.Errorf("CLAUDE.md does not describe the module line as v1.0.0 -> vX.Y.Z")
	}

	const mono = "time must be monotonically non-decreasing across calls."
	checks := []struct {
		path string
		sig  string
	}{
		{"client.go", "func (client *Client) Update(time float64)"},
		{"server.go", "func (server *Server) Update(time float64)"},
	}
	for _, c := range checks {
		src, err := os.ReadFile(c.path)
		if err != nil {
			t.Fatal(err)
		}
		body := string(src)
		i := strings.Index(body, c.sig)
		if i < 0 {
			t.Errorf("%s: %s not found", c.path, c.sig)
			continue
		}
		comment := body[:i]
		if j := strings.LastIndex(comment, "\n\n"); j >= 0 {
			comment = comment[j+2:]
		}
		if !strings.Contains(comment, mono) {
			t.Errorf("%s Update comment lacks %q", c.path, mono)
		}
	}
}
