# IP-Roller Bot

Telegram-бот на Go, который «роллит» публичные/floating IP у облачных
провайдеров до попадания в заданную маску (CIDR или октетный паттерн) и
привязывает подходящий адрес к ВМ. Реализован по спецификации `ip-roller-bot-spec`.

## Как это работает

В Telegram: `/roll` → выбор провайдера → маска → число попыток → запуск.
Движок в цикле `allocate → match → release`: выделяет новый адрес, проверяет
против маски, не подошёл — освобождает и роллит снова; подошёл — резервирует и
кладёт в пул. Соблюдаются rate-limit (token bucket), дневные капы и backoff на 429.

## Архитектура

```
Telegram → bot (UI/FSM) → engine (roll loop + limiter + daily cap + backoff)
                              │  interface Provider
                              ▼
        provider-адаптеры ── storage (SQLite: пул, история, счётчики)
```

- `internal/bot` — команды, FSM-мастер `/roll`, inline-клавиатуры, `acl.go` (whitelist/админы). Не знает деталей провайдеров.
- `internal/engine` — `roller.go` (цикл), `limiter.go` (дневные капы), `mask.go` (CIDR + октетные паттерны).
- `internal/provider` — интерфейс `Provider`, `Account` (обёртка с уникальным ключом) + по адаптеру на сервис.
- `internal/registry` — собирает живые аккаунты из БД (+ дефолты типа из конфига), сид из config при первом старте, hot-reload.
- `internal/storage` — SQLite (pure-Go, `modernc.org/sqlite`): пул, история, счётчики, **accounts**, **allowed_users**.
- `internal/config` — YAML + `${ENV}`.

## Аккаунты и доступ

**Креды провайдеров хранятся в SQL** (таблица `accounts`), а не в env. На каждый
тип провайдера можно завести **несколько аккаунтов** (напр. два Timeweb) — у
каждого свой ключ `тип#id`, поэтому rate-limit и дневной кап считаются по
аккаунту независимо. Поля кред — JSON-блоб; неуказанные не-секретные поля
(region, auth_url, zone) берутся из дефолтов типа в `config.yaml`.

Источник правды — БД. `config.yaml`/env используются только для **сида при
первом старте** (если таблица `accounts` пуста). Дальше — команды бота.

**Доступ:** `admin_user_ids` (в конфиге) — кто управляет аккаунтами и
whitelist'ом; `allowed_user_ids` (в конфиге) — статически разрешённые; плюс
динамический whitelist в SQL (`allowed_users`), управляется командами. Если
пусто всё сразу — доступ открыт всем (с предупреждением в логах).

Управление (только админ):

| Команда | Что делает |
|---------|------------|
| `/accounts` | список аккаунтов (секреты замаскированы) |
| `/addaccount <тип> <label> <json>` | добавить/обновить аккаунт; исходное сообщение с кредами бот удаляет |
| `/enableaccount <id>` · `/disableaccount <id>` | вкл/выкл аккаунт |
| `/delaccount <id>` | удалить аккаунт |
| `/users` | список доступа (админы/конфиг/whitelist) |
| `/adduser <id> [заметка]` · `/deluser <id>` | управление whitelist'ом |

Пример: `/addaccount timeweb prod {"token":"xxx","availability_zone":"spb-1"}`
(`/addaccount` без аргументов печатает поля по каждому типу).

## Статус провайдеров

| Провайдер | Механика | Статус адаптера |
|-----------|----------|-----------------|
| **Timeweb** | floating IP (REST) | ✅ полностью реализован |
| **VK Cloud** | OpenStack/Neutron floating IP (gophercloud) | ✅ реализован |
| **Selectel** | OpenStack/Neutron floating IP (gophercloud) | ✅ реализован |
| **Gcore** | floating IP (REST `apikey`) | ✅ реализован (sync-ответ; async-таски не опрашиваются) |
| **MWS** | reserved IP в подсети (REST) | ✅ allocate/release; attach — при создании ВМ |
| **RuVDS** | пересоздание/доп. IP сервера | ⚠️ каркас: allocate под защитой (нужен `server_id`, платно) |
| **Beget** | заказ доп. IPv4 / пересоздание VPS | ⚠️ каркас: allocate под защитой (нужен `server_id`, платно) |
| IHC/Contell/UFO/Vinton | панель без API | `internal/provider/cookie` — cookie-фолбэк (скелет) |

RuVDS/Beget намеренно не дёргают деструктивные/платные операции без явной
настройки сервера — Allocate возвращает понятную ошибку вместо порчи реальных
серверов. Эндпоинты заказа IP вписываются под конкретный аккаунт.

## Запуск

```bash
cp .env.example .env      # заполни TELEGRAM_TOKEN и токены нужных провайдеров
set -a; source .env; set +a
go run ./cmd/bot -config config.yaml
```

Обязателен только `TELEGRAM_TOKEN`. Креды провайдеров в env — опциональны:
включённые блоки `config.yaml` с заданными `${...}` засеют аккаунты в БД при
первом старте; дальше добавляй аккаунты через `/addaccount`. Доступ ограничь
через `telegram.admin_user_ids` / `allowed_user_ids` (см. «Аккаунты и доступ»).

### Docker Compose

```bash
cp .env.example .env      # заполни TELEGRAM_TOKEN и токены нужных провайдеров
docker compose up -d --build
docker compose logs -f
```

- Бинарь собирается статически (`CGO_ENABLED=0`, SQLite pure-Go) в multi-stage
  образе на базе Alpine, запускается под непривилегированным пользователем.
- `.env` подхватывается через `env_file`; токены подставляются в `config.yaml`
  через `${...}` уже внутри приложения.
- `config.yaml` монтируется read-only — правь локально и `docker compose restart`.
- SQLite-база лежит на томе `botdata` (`STORAGE_DSN=/data/ip-roller.db` перекрывает
  `storage.dsn` из конфига), переживает пересоздание контейнера.
- Порты не публикуются: бот работает long-poll'ом, входящие соединения не нужны.

Остановка / обновление:

```bash
docker compose down              # остановить (том с БД сохраняется)
docker compose up -d --build     # пересобрать и поднять заново
docker compose down -v           # снести вместе с БД-томом
```

## Команды

Пользователь: `/start` · `/roll` · `/pool` · `/attach <ip> <vm_id>` · `/limits` · `/cancel`

Админ: `/accounts` · `/addaccount` · `/delaccount` · `/enableaccount` · `/disableaccount` · `/users` · `/adduser` · `/deluser`

## Тесты / сборка

```bash
go test ./...
go build ./cmd/bot
```

## Безопасность

Секреты только в env (`${VAR}`), не в репозитории. Неподошедшие IP освобождаются
сразу (иначе капают деньги). Джиттер + экспоненциальный backoff на 429.
Least-privilege токены (Application Credential у VK, сервисный пользователь у Selectel).
