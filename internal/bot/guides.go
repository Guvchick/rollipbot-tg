package bot

import (
	"fmt"
	"strings"

	"ip-roller-bot/internal/registry"
)

// providerGuide is an idiot-proof "where do I get the credentials" walkthrough
// shown when an admin adds an account.
type providerGuide struct {
	title   string
	steps   []string
	example string
}

var providerGuides = map[string]providerGuide{
	"timeweb": {
		title: "Timeweb Cloud",
		steps: []string{
			"Зайди в панель https://timeweb.cloud и открой раздел «API и Terraform».",
			"Нажми «Создать токен», скопируй значение — это поле token.",
			"availability_zone (необязательно): зона сервера, напр. spb-1 или msk-1.",
		},
		example: `/addaccount timeweb prod {"token":"ВАШ_ТОКЕН","availability_zone":"spb-1"}`,
	},
	"vkcloud": {
		title: "VK Cloud (OpenStack)",
		steps: []string{
			"Панель VK Cloud → «Управление доступом» → Application credentials → «Добавить».",
			"Сохрани app_credential_id и app_credential_secret (secret показывается ОДИН раз!).",
			"floating_network_id — ID внешней сети: раздел «Сети» → «Внешние сети».",
			"auth_url и region обычно дефолтные (infra.mail.ru:35357/v3, RegionOne) — можно не указывать.",
		},
		example: `/addaccount vkcloud prod {"app_credential_id":"ID","app_credential_secret":"SECRET","floating_network_id":"NET_ID"}`,
	},
	"selectel": {
		title: "Selectel (OpenStack)",
		steps: []string{
			"my.selectel.ru → «Управление доступом» → «Сервисные пользователи» → создай (роль member в нужном проекте).",
			"service_user — имя сервисного пользователя, service_password — его пароль.",
			"account_id — номер аккаунта Selectel (показан вверху панели).",
			"project_id — ID проекта; floating_network_id — ID внешней сети.",
			"region — например ru-9; auth_url по умолчанию cloud.api.selcloud.ru/identity/v3.",
		},
		example: `/addaccount selectel prod {"account_id":"123","service_user":"svc","service_password":"PASS","project_id":"PROJ","floating_network_id":"NET","region":"ru-9"}`,
	},
	"gcore": {
		title: "Gcore",
		steps: []string{
			"Customer Portal → Account → «API tokens» → создай токен → это поле api_token.",
			"project_id и region_id (число) — из раздела Cloud / из URL проекта.",
		},
		example: `/addaccount gcore prod {"api_token":"TOKEN","project_id":"123","region_id":"7"}`,
	},
	"mws": {
		title: "MWS Cloud",
		steps: []string{
			"Панель MWS → токен сервисного аккаунта / API → это поле token.",
			"project_id, network_id, subnetwork_id — из раздела «Сети» проекта.",
		},
		example: `/addaccount mws prod {"token":"TOKEN","project_id":"P","network_id":"N","subnetwork_id":"S"}`,
	},
	"ruvds": {
		title: "RuVDS",
		steps: []string{
			"Личный кабинет → «Настройки» → «Информация API» → скопируй токен (поле token).",
			"server_id — ID сервера, который будем роллить.",
			"⚠️ роллинг RuVDS = пересоздание сервера / заказ доп. IP (платно).",
		},
		example: `/addaccount ruvds prod {"token":"TOKEN","server_id":"12345"}`,
	},
	"beget": {
		title: "Beget",
		steps: []string{
			"developer.beget.com → получи Bearer-токен облачного API → это поле token.",
			"server_id — ID твоего VPS.",
			"⚠️ роллинг Beget = заказ доп. IPv4 / пересоздание VPS (платно).",
		},
		example: `/addaccount beget prod {"token":"TOKEN","server_id":"12345"}`,
	},
}

// guideHTML renders the per-type credential guide as a Telegram HTML message
// (blockquote for the steps, code for the command).
func guideHTML(typ string) string {
	g, ok := providerGuides[typ]
	if !ok {
		return ""
	}
	var req, opt []string
	for _, f := range registry.Fields(typ) {
		if f.Required {
			req = append(req, f.Name)
		} else {
			opt = append(opt, f.Name)
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s — как получить креды</b>\n", htmlEsc(g.title))
	sb.WriteString("<blockquote expandable>")
	for i, s := range g.steps {
		fmt.Fprintf(&sb, "%d. %s\n", i+1, htmlEsc(s))
	}
	sb.WriteString("</blockquote>\n")
	fmt.Fprintf(&sb, "Обязательные поля: <b>%s</b>\n", htmlEsc(strings.Join(req, ", ")))
	if len(opt) > 0 {
		fmt.Fprintf(&sb, "Необязательные: %s\n", htmlEsc(strings.Join(opt, ", ")))
	}
	sb.WriteString("Все значения в JSON — строками (region_id тоже: \"7\").\n")
	sb.WriteString("Пример:\n<code>" + htmlEsc(g.example) + "</code>")
	return sb.String()
}

// generalAddHelpHTML is shown for /addaccount with no type.
func generalAddHelpHTML() string {
	var sb strings.Builder
	sb.WriteString("<b>Добавление аккаунта провайдера</b>\n")
	sb.WriteString("Формат: <code>/addaccount [тип] [label] [json]</code>\n")
	sb.WriteString("Пошаговый гайд по типу: пришли <code>/addaccount [тип]</code> ")
	sb.WriteString("(напр. <code>/addaccount timeweb</code>).\n\n")
	sb.WriteString("Типы и обязательные поля:\n<blockquote expandable>")
	for _, t := range registry.Types {
		var req []string
		for _, f := range registry.Fields(t) {
			if f.Required {
				req = append(req, f.Name)
			}
		}
		fmt.Fprintf(&sb, "%s: %s\n", t, strings.Join(req, ", "))
	}
	sb.WriteString("</blockquote>")
	return sb.String()
}

// htmlEsc escapes the three characters that matter in Telegram HTML mode.
func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// stripTags is the plain-text fallback if a Telegram HTML send is rejected.
func stripTags(s string) string {
	r := strings.NewReplacer(
		"<blockquote expandable>", "", "<blockquote>", "", "</blockquote>", "",
		"<b>", "", "</b>", "", "<code>", "", "</code>", "",
		"&lt;", "<", "&gt;", ">", "&amp;", "&",
	)
	return r.Replace(s)
}
