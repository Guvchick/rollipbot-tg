// Command bot is the IP-Roller Telegram bot entry point: it loads config, opens
// storage, seeds provider accounts from config on first run, builds the live
// account registry and user ACL, and starts the bot.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"ip-roller-bot/internal/bot"
	"ip-roller-bot/internal/config"
	"ip-roller-bot/internal/engine"
	"ip-roller-bot/internal/registry"
	"ip-roller-bot/internal/storage"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config.yaml")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(*configPath, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(configPath string, log *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := storage.NewSQLite(ctx, cfg.Storage.DSN)
	if err != nil {
		return err
	}
	defer store.Close()

	// First run: move credentials from config/env into the accounts table.
	if err := registry.SeedFromConfig(ctx, store, cfg, log); err != nil {
		return err
	}

	eng := engine.New(store, log)

	reg := registry.New(cfg, store, log)
	if err := reg.Reload(ctx); err != nil {
		return err
	}
	if reg.Len() == 0 {
		log.Warn("нет включённых аккаунтов — /roll будет недоступен, добавь через /addaccount")
	}

	acl := bot.NewACL(store, log, cfg.Telegram.AdminUserIDs, cfg.Telegram.AllowedUserIDs)
	if err := acl.Reload(ctx); err != nil {
		return err
	}

	return bot.Run(ctx, cfg, eng, store, reg, acl, log)
}
