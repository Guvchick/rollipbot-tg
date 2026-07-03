package bot

import (
	"strings"
	"testing"

	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/registry"
)

// Every credential field of every provider must have a specific wizard hint, so
// the button flow is truly idiot-proof (no generic "Введи значение поля X").
func TestEveryFieldHasSpecificHint(t *testing.T) {
	for _, typ := range registry.Types {
		for _, f := range registry.Fields(typ) {
			h := fieldHint(typ, f.Name)
			if h == "" || strings.HasPrefix(h, "Введи значение поля ") {
				t.Errorf("%s/%s has no specific hint (got %q)", typ, f.Name, h)
			}
		}
	}
}

func TestFieldHintFallback(t *testing.T) {
	if got := fieldHint("timeweb", "does_not_exist"); got != "Введи значение поля does_not_exist." {
		t.Errorf("fallback hint = %q", got)
	}
}

// The type picker must offer a button for every registered provider type.
func TestAddTypeKeyboardCoversAllTypes(t *testing.T) {
	kb := addTypeKeyboard()
	seen := map[string]bool{}
	for _, row := range kb.InlineKeyboard {
		for _, btn := range row {
			if strings.HasPrefix(btn.CallbackData, "addtype:") {
				seen[strings.TrimPrefix(btn.CallbackData, "addtype:")] = true
			}
		}
	}
	for _, typ := range registry.Types {
		if !seen[typ] {
			t.Errorf("type picker missing button for %q", typ)
		}
	}
}

func TestGuideStepsHTMLSafeForAllTypes(t *testing.T) {
	for _, typ := range registry.Types {
		g := guideStepsHTML(typ)
		if g == "" {
			t.Errorf("no wizard guide steps for %q", typ)
			continue
		}
		if !strings.Contains(g, "<blockquote") {
			t.Errorf("%s wizard guide missing blockquote", typ)
		}
		// wizard guide must not push the old command-based flow
		if strings.Contains(g, "/addaccount") {
			t.Errorf("%s wizard guide should not reference /addaccount", typ)
		}
	}
}

func TestAddFieldKeyboardSkipButton(t *testing.T) {
	// optional field: skip present
	optional := addFieldKeyboard(true)
	if !hasCallback(optional, "addskip") {
		t.Error("optional field keyboard must offer skip")
	}
	// required field: no skip
	required := addFieldKeyboard(false)
	if hasCallback(required, "addskip") {
		t.Error("required field keyboard must not offer skip")
	}
	// both must offer cancel back to accounts
	if !hasCallback(optional, "acc:cancel") || !hasCallback(required, "acc:cancel") {
		t.Error("field keyboard must offer cancel")
	}
}

func hasCallback(kb *models.InlineKeyboardMarkup, data string) bool {
	for _, row := range kb.InlineKeyboard {
		for _, btn := range row {
			if btn.CallbackData == data {
				return true
			}
		}
	}
	return false
}
