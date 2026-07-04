package bot

import (
	"fmt"

	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/provider"
	"ip-roller-bot/internal/registry"
	"ip-roller-bot/internal/storage"
)

// typeNames maps provider type to a pretty label.
var typeNames = map[string]string{
	"timeweb":  "Timeweb",
	"vkcloud":  "VK Cloud",
	"selectel": "Selectel",
	"gcore":    "Gcore",
	"mws":      "MWS",
	"ruvds":    "RuVDS",
	"beget":    "Beget",
}

func typeName(t string) string {
	if d, ok := typeNames[t]; ok {
		return d
	}
	return t
}

// accountDisplay renders an account as "Type · label".
func accountDisplay(a *provider.Account) string {
	return typeName(a.Type()) + " · " + a.Label()
}

func cancelRow() []models.InlineKeyboardButton {
	return []models.InlineKeyboardButton{{Text: "✖️ Отмена", CallbackData: "cancel"}}
}

// mainMenu is the single entry-point menu for the admin.
func mainMenu() *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{{Text: "🎲 Ролл", CallbackData: "menu:roll"}},
		{
			{Text: "📦 Пул", CallbackData: "menu:pool"},
			{Text: "📈 Статистика", CallbackData: "menu:stats"},
		},
		{
			{Text: "🔐 Аккаунты", CallbackData: "menu:accounts"},
			{Text: "🌐 Прокси", CallbackData: "menu:proxies"},
		},
	}}
}

func backToMenuRow() []models.InlineKeyboardButton {
	return []models.InlineKeyboardButton{{Text: "⬅️ Меню", CallbackData: "menu:back"}}
}

// menuBackKeyboard is a single "back to main menu" row for info screens.
func menuBackKeyboard() *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{backToMenuRow()}}
}

// accountsMenu lists accounts with per-account toggle/delete and an add button.
func accountsMenu(accs []accountRow) *models.InlineKeyboardMarkup {
	var rows [][]models.InlineKeyboardButton
	for _, a := range accs {
		flag := "✅"
		if !a.Enabled {
			flag = "⛔"
		}
		px := "🌐"
		if a.Proxy != "" {
			px = "🌐✓"
		}
		rows = append(rows, []models.InlineKeyboardButton{
			{Text: fmt.Sprintf("%s %s", flag, a.Display), CallbackData: fmt.Sprintf("acc:toggle:%d", a.ID)},
			{Text: px, CallbackData: fmt.Sprintf("acc:proxy:%d", a.ID)},
			{Text: "🗑", CallbackData: fmt.Sprintf("acc:del:%d", a.ID)},
		})
	}
	rows = append(rows,
		[]models.InlineKeyboardButton{{Text: "➕ Добавить аккаунт", CallbackData: "acc:add"}},
		backToMenuRow(),
	)
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

// addTypeKeyboard lists provider types for the first step of the add wizard.
func addTypeKeyboard() *models.InlineKeyboardMarkup {
	var rows [][]models.InlineKeyboardButton
	row := []models.InlineKeyboardButton{}
	for _, t := range registry.Types {
		row = append(row, models.InlineKeyboardButton{Text: typeName(t), CallbackData: "addtype:" + t})
		if len(row) == 2 {
			rows = append(rows, row)
			row = []models.InlineKeyboardButton{}
		}
	}
	if len(row) > 0 {
		rows = append(rows, row)
	}
	rows = append(rows, []models.InlineKeyboardButton{{Text: "⬅️ К аккаунтам", CallbackData: "acc:list"}})
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

// addFieldKeyboard is shown while collecting one credential field: a skip button
// for optional fields plus a cancel that returns to the accounts view.
func addFieldKeyboard(optional bool) *models.InlineKeyboardMarkup {
	var rows [][]models.InlineKeyboardButton
	if optional {
		rows = append(rows, []models.InlineKeyboardButton{{Text: "⏭ Пропустить", CallbackData: "addskip"}})
	}
	rows = append(rows, []models.InlineKeyboardButton{{Text: "✖️ Отмена", CallbackData: "acc:cancel"}})
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

// addLabelKeyboard is shown on the final (label) step: skip to auto-name, or
// cancel back to the accounts view.
func addLabelKeyboard() *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{{Text: "⏭ Пропустить (назову сам)", CallbackData: "addskip"}},
		{{Text: "✖️ Отмена", CallbackData: "acc:cancel"}},
	}}
}

// addDoneKeyboard is shown after an account is saved.
func addDoneKeyboard() *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{{Text: "➕ Ещё аккаунт", CallbackData: "acc:add"}},
		{{Text: "⬅️ К аккаунтам", CallbackData: "acc:list"}},
	}}
}

// accountRow is the minimal account view the keyboard needs.
type accountRow struct {
	ID      int64
	Display string
	Enabled bool
	Proxy   string // bound proxy label, empty if none
}

// proxiesMenu lists proxies (delete each) plus add + back.
func proxiesMenu(proxies []storage.Proxy) *models.InlineKeyboardMarkup {
	var rows [][]models.InlineKeyboardButton
	for _, p := range proxies {
		rows = append(rows, []models.InlineKeyboardButton{
			{Text: fmt.Sprintf("🌐 %s · %s (%s:%d)", p.Scheme, p.Label, p.Host, p.Port), CallbackData: "px:list"},
			{Text: "🗑", CallbackData: fmt.Sprintf("px:del:%d", p.ID)},
		})
	}
	rows = append(rows,
		[]models.InlineKeyboardButton{{Text: "➕ Добавить прокси", CallbackData: "px:add"}},
		backToMenuRow(),
	)
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

// proxyLineKeyboard is the cancel row shown while waiting for the proxy line.
func proxyLineKeyboard() *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{{Text: "✖️ Отмена", CallbackData: "px:list"}},
	}}
}

// proxySchemeKeyboard picks the proxy scheme at the start of the add wizard.
func proxySchemeKeyboard() *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{
			{Text: "SOCKS5", CallbackData: "pxscheme:socks5"},
			{Text: "HTTP", CallbackData: "pxscheme:http"},
		},
		{{Text: "⬅️ Назад", CallbackData: "px:list"}},
	}}
}

// accountProxyPicker lets an account pick one of the proxies (or none).
func accountProxyPicker(accountID int64, proxies []storage.Proxy, currentID int64) *models.InlineKeyboardMarkup {
	var rows [][]models.InlineKeyboardButton
	for _, p := range proxies {
		mark := ""
		if p.ID == currentID {
			mark = "✓ "
		}
		rows = append(rows, []models.InlineKeyboardButton{{
			Text:         fmt.Sprintf("%s🌐 %s · %s", mark, p.Scheme, p.Label),
			CallbackData: fmt.Sprintf("accpx:%d:%d", accountID, p.ID),
		}})
	}
	none := "❌ Без прокси"
	if currentID == 0 {
		none = "✓ ❌ Без прокси"
	}
	rows = append(rows,
		[]models.InlineKeyboardButton{{Text: none, CallbackData: fmt.Sprintf("accpx:%d:0", accountID)}},
		[]models.InlineKeyboardButton{{Text: "⬅️ К аккаунтам", CallbackData: "acc:list"}},
	)
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

// providerKeyboard lists enabled accounts, one per row (labels can be long).
func providerKeyboard(accs []*provider.Account) *models.InlineKeyboardMarkup {
	var rows [][]models.InlineKeyboardButton
	for _, a := range accs {
		rows = append(rows, []models.InlineKeyboardButton{
			{Text: accountDisplay(a), CallbackData: "prov:" + a.Key()},
		})
	}
	rows = append(rows, cancelRow())
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

// maskKeyboard offers preset masks from config plus a cancel button.
func maskKeyboard(masks []string) *models.InlineKeyboardMarkup {
	var rows [][]models.InlineKeyboardButton
	for _, m := range masks {
		rows = append(rows, []models.InlineKeyboardButton{
			{Text: m, CallbackData: "mask:" + m},
		})
	}
	rows = append(rows, cancelRow())
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

func budgetKeyboard() *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{
			{Text: "5", CallbackData: "budget:5"},
			{Text: "10", CallbackData: "budget:10"},
			{Text: "25", CallbackData: "budget:25"},
			{Text: "макс", CallbackData: "budget:max"},
		},
		cancelRow(),
	}}
}

func confirmKeyboard() *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{
			{Text: "▶️ Запустить", CallbackData: "run"},
			{Text: "✖️ Отмена", CallbackData: "cancel"},
		},
	}}
}

func resultKeyboard(poolID int64) *models.InlineKeyboardMarkup {
	return &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{
		{
			{Text: "🔗 Привязать к ВМ", CallbackData: fmt.Sprintf("attach:%d", poolID)},
			{Text: "✅ Оставить в пуле", CallbackData: "pool"},
		},
		backToMenuRow(),
	}}
}
