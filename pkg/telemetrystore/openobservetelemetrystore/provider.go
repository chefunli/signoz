package openobservetelemetrystore

import (
	"context"
	"log/slog"

	"github.com/SigNoz/signoz/pkg/factory"
	"github.com/SigNoz/signoz/pkg/telemetrystore"
	"github.com/SigNoz/signoz/pkg/types/telemetrystoretypes"
)

type provider struct {
	conn    *ooConn
	config  Config
	logger  *slog.Logger
}

// Config holds OpenObserve connection configuration.
type Config struct {
	// Endpoint is the OpenObserve API endpoint (e.g., http://localhost:5080).
	Endpoint string `mapstructure:"endpoint"`

	// OrgID is the OpenObserve organization ID.
	OrgID string `mapstructure:"org_id"`

	// Username for Basic Auth.
	Username string `mapstructure:"username"`

	// Password for Basic Auth.
	Password string `mapstructure:"password"`
}

func NewFactory(hookFactories ...factory.ProviderFactory[telemetrystore.TelemetryStoreHook, telemetrystore.Config]) factory.ProviderFactory[telemetrystore.TelemetryStore, telemetrystore.Config] {
	return factory.NewProviderFactory(factory.MustNewName("openobserve"), func(ctx context.Context, providerSettings factory.ProviderSettings, config telemetrystore.Config) (telemetrystore.TelemetryStore, error) {
		return newProvider(ctx, providerSettings, config)
	})
}

func newProvider(ctx context.Context, providerSettings factory.ProviderSettings, config telemetrystore.Config) (telemetrystore.TelemetryStore, error) {
	ooConfig := config.Openobserve
	if ooConfig.Endpoint == "" {
		ooConfig.Endpoint = "http://localhost:5080"
	}
	if ooConfig.OrgID == "" {
		ooConfig.OrgID = "default"
	}

	conn := newOOConn(ooConfig.Endpoint, ooConfig.OrgID, ooConfig.Username, ooConfig.Password, providerSettings.Logger)

	return &provider{
		conn:   conn,
		config: Config{Endpoint: ooConfig.Endpoint, OrgID: ooConfig.OrgID, Username: ooConfig.Username, Password: ooConfig.Password},
		logger: providerSettings.Logger,
	}, nil
}

func (p *provider) DB() telemetrystore.Conn {
	return p.conn
}

func (p *provider) Cluster() string {
	return ""
}

func (p *provider) Estimate(ctx context.Context, stmt string, args ...any) ([]telemetrystoretypes.EstimateEntry, error) {
	// OpenObserve does not support EXPLAIN ESTIMATE.
	// Return empty result.
	return nil, nil
}

func (p *provider) Plan(ctx context.Context, stmt string, args ...any) error {
	// OpenObserve does not support EXPLAIN PLAN.
	// Return nil (no error) to indicate the query is valid.
	return nil
}

func (p *provider) Indexes(ctx context.Context, stmt string, args ...any) (telemetrystoretypes.Granules, bool, error) {
	// OpenObserve does not support EXPLAIN indexes.
	// Return empty result.
	return telemetrystoretypes.Granules{}, false, nil
}

func (p *provider) Start(ctx context.Context) error {
	return nil
}

func (p *provider) Stop(ctx context.Context) error {
	return nil
}

// Ensure provider satisfies the interface at compile time.
var _ telemetrystore.TelemetryStore = (*provider)(nil)
