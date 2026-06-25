package bot

import (
	"fmt"

	"github.com/go-telegram/bot/models"

	"ip-roller-bot/internal/provider"
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
			{Text: "📊 Лимиты", CallbackData: "menu:limits"},
		},
		{{Text: "🔐 Аккаунты", CallbackData: "menu:accounts"}},
	}}
}

func backToMenuRow() []models.InlineKeyboardButton {
	return []models.InlineKeyboardButton{{Text: "⬅️ Меню", CallbackData: "menu:back"}}
}

// accountsMenu lists accounts with per-account toggle/delete and an add button.
func accountsMenu(accs []accountRow) *models.InlineKeyboardMarkup {
	var rows [][]models.InlineKeyboardButton
	for _, a := range accs {
		flag := "✅"
		if !a.Enabled {
			flag = "⛔"
		}
		rows = append(rows, []models.InlineKeyboardButton{
			{Text: fmt.Sprintf("%s %s", flag, a.Display), CallbackData: fmt.Sprintf("acc:toggle:%d", a.ID)},
			{Text: "🗑", CallbackData: fmt.Sprintf("acc:del:%d", a.ID)},
		})
	}
	rows = append(rows,
		[]models.InlineKeyboardButton{{Text: "➕ Добавить (гайд)", CallbackData: "acc:addhelp"}},
		backToMenuRow(),
	)
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

// accountRow is the minimal account view the keyboard needs.
type accountRow struct {
	ID      int64
	Display string
	Enabled bool
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
	}}
}
