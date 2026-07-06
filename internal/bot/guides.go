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
		title: "VK Cloud (OpenStack, парольная авторизация)",
		steps: []string{
			"⚠️ VK Cloud НЕ поддерживает application credentials для API — только логин/пароль. Панель → «Настройки проекта» → «API-доступ».",
			"Включи API-доступ (может потребоваться 2FA). Скачай файл openrc (rc-файл OpenStack) — там все нужные значения.",
			"username — твой логин (email аккаунта) из openrc (OS_USERNAME). password — пароль (OS_PASSWORD).",
			"project_id — ID проекта (OS_PROJECT_ID), region — OS_REGION_NAME (обычно RegionOne).",
			"auth_url — OS_AUTH_URL (обычно https://infra.mail.ru:35357/v3/). user_domain_name — OS_USER_DOMAIN_NAME (обычно users).",
			"floating_network_id — UUID внешней сети: «Сети» → «Внешние сети» → открой ext-net → ID.",
			"Проверь квоту: «Квоты» → Network → Floating IPs > 0.",
		},
		example: `/addaccount vkcloud prod {"username":"you@mail","password":"PASS","project_id":"PID","floating_network_id":"NET_ID"}`,
	},
	"yandex": {
		title: "Yandex Cloud (статический IP)",
		steps: []string{
			"Получи OAuth-токен Яндекса: открой https://oauth.yandex.ru/authorize?response_type=token&client_id=1a6990aa636648e9b2ef855fa7bec2fb (это client_id Yandex Cloud CLI) и скопируй токен из адресной строки.",
			"Токен положи в поле oauth_token. Бот сам обменяет его на короткоживущий IAM-токен.",
			"folder_id — ID каталога (folder): консоль console.yandex.cloud → нужный каталог → в обзоре есть «Идентификатор».",
			"zone_id — зона доступности: ru-central1-a / ru-central1-b / ru-central1-d.",
			"Проверь квоту на статические внешние адреса в разделе «Quotas» каталога.",
			"⚠️ Роллинг = резервирование static IP (тарифицируется, пока не удалён — бот удаляет непопавшие).",
		},
		example: `/addaccount yandex prod {"oauth_token":"AQAA...","folder_id":"b1g...","zone_id":"ru-central1-a"}`,
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
		title: "MWS Cloud Platform (MTS Web Services)",
		steps: []string{
			"Кнопка «Создать» в консоли даёт 3 типа ключей: «Авторизованный ключ», «HMAC-ключ» (только Object Storage) и «API-ключ» (v1.…, только Artifact Registry/GPT). Для роллинга IP годится ТОЛЬКО «Авторизованный ключ».",
			"⚠️ Публичный ключ (MFkw…), который консоль показывает в списке ключей, боту НЕ нужен — нужна ПРИВАТНАЯ часть пары.",
			"Вариант А: создай «Авторизованный ключ» и СКАЧАЙ предложенный JSON (приватная часть отдаётся один раз!) → вставь весь файл на шаге private_key — разберу его сам.",
			"Вариант Б: сгенерь пару сам: openssl ecparam -name prime256v1 -genkey -noout -out priv.pem ; openssl ec -in priv.pem -pubout -out pub.pem → при создании ключа отметь «Добавить существующий ключ доступа», выбери алгоритм ES256 (если консоль спрашивает) и вставь pub.pem.",
			"Для варианта Б: private_key = содержимое priv.pem; дальше можно вставить одним куском путь ключа (iam/projects/…/serviceAccounts/…/authorizedKeys/…) — key_id, service_account_id и project_id подставятся сами.",
			"project_id = ID проекта. Бот сам подпишет IAM-токен (ES256 JWT) и будет обновлять его. Публичный IP роллится на https://vpc.mwsapis.ru (дефолт).",
		},
		example: `/addaccount mws prod {"private_key":"-----BEGIN PRIVATE KEY-----\n...","key_id":"access-key-r60vh0","service_account_id":"SA","project_id":"P"}`,
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

// fieldHints gives a one-line, idiot-proof explanation for every credential
// field, shown at each step of the button-driven add-account wizard. Optional
// fields say so and mention their default.
var fieldHints = map[string]map[string]string{
	"timeweb": {
		"token":             "API-токен: панель timeweb.cloud → «API и Terraform» → «Создать токен».",
		"availability_zone": "Зона сервера, напр. spb-1 или msk-1. Необязательно — можно пропустить.",
	},
	"vkcloud": {
		"username":            "Логин/email аккаунта (OS_USERNAME из openrc-файла).",
		"password":            "Пароль (OS_PASSWORD). VK Cloud API работает только по логину/паролю.",
		"project_id":          "ID проекта (OS_PROJECT_ID из openrc).",
		"floating_network_id": "UUID внешней сети: «Сети» → «Внешние сети» → open ext-net → ID.",
		"auth_url":            "OS_AUTH_URL, обычно https://infra.mail.ru:35357/v3/. Необязательно.",
		"region":              "OS_REGION_NAME, обычно RegionOne. Необязательно.",
		"user_domain_name":    "OS_USER_DOMAIN_NAME, обычно users. Необязательно.",
	},
	"selectel": {
		"account_id":          "Номер аккаунта Selectel (показан вверху панели my.selectel.ru).",
		"service_user":        "Имя сервисного пользователя («Управление доступом» → «Сервисные пользователи»).",
		"service_password":    "Пароль этого сервисного пользователя.",
		"project_id":          "ID проекта, в котором роллим.",
		"floating_network_id": "ID внешней сети проекта.",
		"auth_url":            "По умолчанию https://cloud.api.selcloud.ru/identity/v3. Необязательно.",
		"region":              "Напр. ru-9. Необязательно — можно пропустить.",
	},
	"yandex": {
		"oauth_token": "OAuth-токен Яндекса (oauth.yandex.ru, client_id Yandex Cloud CLI). Бот обменяет его на IAM.",
		"folder_id":   "ID каталога (folder) из консоли console.yandex.cloud → каталог → «Идентификатор».",
		"zone_id":     "Зона: ru-central1-a / ru-central1-b / ru-central1-d.",
		"api_url":     "База VPC API. Обычно дефолт (https://vpc.api.cloud.yandex.net/vpc/v1). Необязательно.",
	},
	"gcore": {
		"api_token":  "Токен: Customer Portal → Account → «API tokens» → создать.",
		"project_id": "ID проекта (раздел Cloud / из URL проекта).",
		"region_id":  "Число региона, напр. 7.",
		"api_url":    "Обычно дефолтный. Необязательно — можно пропустить.",
	},
	"mws": {
		"authorized_key":     "Весь JSON, скачанный при создании «Авторизованного ключа». Если генерил пару сам и уже ввёл private_key — ПРОПУСТИ. НЕ публичный ключ MFkw…, НЕ API-ключ v1.… и НЕ HMAC!",
		"private_key":        "ПРИВАТНЫЙ ключ PEM (-----BEGIN … PRIVATE KEY-----) — твой priv.pem. Либо вставь сюда ВЕСЬ скачанный JSON ключа — разберу и заполню остальные поля сам. НЕ публичный (MFkw…)!",
		"key_id":             "ID авторизованного ключа (напр. access-key-r60vh0) — в списке ключей. Можно вставить целиком путь iam/projects/…/serviceAccounts/…/authorizedKeys/… — подставлю все ID сам.",
		"service_account_id": "Имя/ID сервисного аккаунта — сегмент URL консоли после service-accounts/: …/service-accounts/<вот_это>/access-keys.",
		"token":              "Готовый IAM-токен (eyJ….) из `mws iam create-token` — временная альтернатива ключу, протухает. Обычно ПРОПУСТИ.",
		"project_id":     "ID проекта — сегмент URL консоли после /iam/: console.mws.ru/iam/<вот_это>/… (напр. project-foxday128).",
		"api_url":        "База VPC API. По умолчанию https://vpc.mwsapis.ru — пропусти.",
		"iam_url":        "Не используется (IAM-токен подписывается локально, обмена нет). Пропусти.",
		"region":         "Регион, если требуется. Необязательно.",
		"network_id":     "Обычно НЕ нужен для внешнего адреса. Необязательно.",
		"subnetwork_id":  "Обычно НЕ нужен для внешнего адреса. Необязательно.",
	},
	"ruvds": {
		"token":     "Токен: Личный кабинет → «Настройки» → «Информация API».",
		"server_id": "ID сервера, который будем роллить. ⚠️ роллинг = пересоздание/доп. IP (платно).",
	},
	"beget": {
		"token":     "Bearer-токен облачного API (developer.beget.com).",
		"server_id": "ID твоего VPS. ⚠️ роллинг = заказ доп. IPv4 / пересоздание (платно).",
		"api_url":   "Обычно дефолтный. Необязательно — можно пропустить.",
	},
}

// fieldHint returns the human hint for a field, or a generic fallback.
func fieldHint(typ, name string) string {
	if m, ok := fieldHints[typ]; ok {
		if h, ok := m[name]; ok {
			return h
		}
	}
	return "Введи значение поля " + name + "."
}

// guideStepsHTML renders just the "where to get the credentials" steps for a
// provider type as an expandable blockquote — used at the start of the
// button-driven wizard (no /addaccount command example).
func guideStepsHTML(typ string) string {
	g, ok := providerGuides[typ]
	if !ok {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("<blockquote expandable>📖 Где взять креды:\n")
	for i, s := range g.steps {
		fmt.Fprintf(&sb, "%d. %s\n", i+1, htmlEsc(s))
	}
	sb.WriteString("</blockquote>")
	return sb.String()
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
