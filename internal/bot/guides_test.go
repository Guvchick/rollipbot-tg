package bot

import (
	"strings"
	"testing"

	"ip-roller-bot/internal/registry"
)

func TestEveryProviderTypeHasGuide(t *testing.T) {
	for _, typ := range registry.Types {
		g := guideHTML(typ)
		if g == "" {
			t.Errorf("no guide for provider type %q", typ)
			continue
		}
		if !strings.Contains(g, "<blockquote") {
			t.Errorf("%s guide missing blockquote", typ)
		}
		if !strings.Contains(g, "/addaccount "+typ) {
			t.Errorf("%s guide missing example command", typ)
		}
		// every required field must be mentioned somewhere in the guide
		for _, f := range registry.Fields(typ) {
			if f.Required && !strings.Contains(g, f.Name) {
				t.Errorf("%s guide does not mention required field %q", typ, f.Name)
			}
		}
	}
}

func TestHTMLEscape(t *testing.T) {
	if got := htmlEsc("a<b>&c"); got != "a&lt;b&gt;&amp;c" {
		t.Errorf("htmlEsc = %q", got)
	}
}

func TestStripTagsRoundTrip(t *testing.T) {
	plain := stripTags(guideHTML("timeweb"))
	for _, tag := range []string{"<blockquote", "<b>", "<code>", "&lt;", "&amp;"} {
		if strings.Contains(plain, tag) {
			t.Errorf("stripTags left %q in fallback text", tag)
		}
	}
	if !strings.Contains(plain, "Timeweb") {
		t.Error("stripTags removed real content")
	}
}

func TestGeneralAddHelpIsHTMLSafe(t *testing.T) {
	h := generalAddHelpHTML()
	// must not contain a raw '<' that isn't part of an allowed tag
	if strings.Contains(h, "<тип>") {
		t.Error("general help uses raw <тип> which breaks HTML parse mode")
	}
}
