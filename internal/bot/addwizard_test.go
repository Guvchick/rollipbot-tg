package bot

import (
	"context"
	"strings"
	"testing"

	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/registry"
	"ip-roller-bot/internal/storage"
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

func TestSingleRequiredField(t *testing.T) {
	if got := singleRequiredField("timeweb"); got != "token" {
		t.Errorf("timeweb single required = %q, want token", got)
	}
	// providers with several required fields have no single bare-token shortcut
	for _, typ := range []string{"vkcloud", "selectel", "gcore", "mws", "ruvds", "beget"} {
		if got := singleRequiredField(typ); got != "" {
			t.Errorf("%s should have no single required field, got %q", typ, got)
		}
	}
}

func TestLooksLikeToken(t *testing.T) {
	jwt := "eyJhbGciOiJSUzUxMiJ9.eyJ1c2VyIjoibWI3MzM2OCJ9.O2MeOvUBYffqQ2wXK10cJfh5"
	if !looksLikeToken(jwt) {
		t.Error("JWT should look like a token")
	}
	if looksLikeToken("prod") {
		t.Error("short plain label must not look like a token")
	}
	if !looksLikeToken(strings.Repeat("a", 41)) {
		t.Error("long string should look like a token")
	}
}

func TestParseCredsArg(t *testing.T) {
	// JSON form
	creds, err := parseCredsArg("vkcloud", `{"app_credential_id":"a","app_credential_secret":"b","floating_network_id":"c"}`)
	if err != nil || creds["app_credential_id"] != "a" {
		t.Fatalf("json parse failed: %v %v", creds, err)
	}
	// bare token for a single-required-field type
	creds, err = parseCredsArg("timeweb", "eyJ.tokenlike.value")
	if err != nil || creds["token"] != "eyJ.tokenlike.value" {
		t.Fatalf("bare token parse failed: %v %v", creds, err)
	}
	// bare value rejected for a multi-field type
	if _, err := parseCredsArg("vkcloud", "justatoken"); err == nil {
		t.Error("multi-field type must reject a bare value")
	}
}

func TestAddLabelKeyboardIsSkippable(t *testing.T) {
	kb := addLabelKeyboard()
	if !hasCallback(kb, "addskip") {
		t.Error("label step must offer a skip button")
	}
	if !hasCallback(kb, "acc:cancel") {
		t.Error("label step must offer cancel")
	}
}

func TestSplitMasks(t *testing.T) {
	cases := map[string][]string{
		// the exact multiline paste from the bug report
		"81.200.148.0/22\n94.228.117.0/24\n188.120.228.0/24": {"81.200.148.0/22", "94.228.117.0/24", "188.120.228.0/24"},
		"185.12.0.0/16, 95.142.*.*":                          {"185.12.0.0/16", "95.142.*.*"},
		"185.12.0.0/16 95.142.*.*":                           {"185.12.0.0/16", "95.142.*.*"},
		"185.12.0.0/16;95.142.*.*":                           {"185.12.0.0/16", "95.142.*.*"},
		"  185.12.0.0/16  ":                                  {"185.12.0.0/16"},
		"":                                                   {},
	}
	for in, want := range cases {
		got := splitMasks(in)
		if len(got) != len(want) {
			t.Errorf("splitMasks(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("splitMasks(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
	// ranges keep their hyphen (must not be treated as a separator)
	if got := splitMasks("95.142.0-50.*"); len(got) != 1 || got[0] != "95.142.0-50.*" {
		t.Errorf("range mask split wrong: %v", got)
	}
}

func TestUniqueLabelAvoidsCollisions(t *testing.T) {
	ctx := context.Background()
	h := &Handler{store: aclStore(t)}
	if got := h.uniqueLabel(ctx, "timeweb"); got != "default" {
		t.Fatalf("first label = %q, want default", got)
	}
	if _, err := h.store.UpsertAccount(ctx, storage.Account{Provider: "timeweb", Label: "default", Enabled: true, Credentials: map[string]string{"token": "x"}}); err != nil {
		t.Fatal(err)
	}
	if got := h.uniqueLabel(ctx, "timeweb"); got != "default-2" {
		t.Errorf("second label = %q, want default-2", got)
	}
	// a different provider type is unaffected
	if got := h.uniqueLabel(ctx, "beget"); got != "default" {
		t.Errorf("other-type label = %q, want default", got)
	}
}
