package main
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/SigNoz/signoz/pkg/config"
	"github.com/SigNoz/signoz/pkg/config/envprovider"
	"github.com/SigNoz/signoz/pkg/config/fileprovider"
	"github.com/SigNoz/signoz/pkg/signoz"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()

	uris := []string{"env:"}

	conf, err := signoz.NewConfig(
		ctx,
		logger,
		config.ResolverConfig{
			Uris: uris,
			ProviderFactories: []config.ProviderFactory{
				envprovider.NewFactory(),
				fileprovider.NewFactory(),
			},
		},
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Config loaded successfully. User root enabled: %v\n", conf.User.Root.Enabled)
	fmt.Printf("User root email: %v\n", conf.User.Root.Email)
}
