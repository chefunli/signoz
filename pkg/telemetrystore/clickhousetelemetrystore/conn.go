package clickhousetelemetrystore

import (
	"context"
	"reflect"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/SigNoz/signoz/pkg/telemetrystore"
)

// columnTypeAdapter wraps driver.ColumnType to implement telemetrystore.ColumnType.
type columnTypeAdapter struct {
	ct driver.ColumnType
}

func (c *columnTypeAdapter) Name() string             { return c.ct.Name() }
func (c *columnTypeAdapter) DatabaseTypeName() string  { return c.ct.DatabaseTypeName() }
func (c *columnTypeAdapter) ScanType() reflect.Type    { return c.ct.ScanType() }

// rowsAdapter wraps driver.Rows to implement telemetrystore.Rows.
type rowsAdapter struct {
	driver.Rows
}

func (r *rowsAdapter) Columns() ([]string, error) {
	return r.Rows.Columns(), nil
}

func (r *rowsAdapter) ColumnTypes() ([]telemetrystore.ColumnType, error) {
	driverTypes := r.Rows.ColumnTypes()
	result := make([]telemetrystore.ColumnType, len(driverTypes))
	for i, ct := range driverTypes {
		result[i] = &columnTypeAdapter{ct: ct}
	}
	return result, nil
}

// rowAdapter wraps driver.Row to implement telemetrystore.Row.
type rowAdapter struct {
	driver.Row
}

// batchAdapter wraps driver.Batch to implement telemetrystore.Batch.
type batchAdapter struct {
	driver.Batch
}

// connWrapper wraps clickhouse.Conn to implement telemetrystore.Conn.
// It adapts the return types from driver-specific to generic interfaces.
type connWrapper struct {
	conn clickhouse.Conn
}

func (c *connWrapper) Query(ctx context.Context, query string, args ...any) (telemetrystore.Rows, error) {
	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return &rowsAdapter{Rows: rows}, nil
}

func (c *connWrapper) QueryRow(ctx context.Context, query string, args ...any) telemetrystore.Row {
	row := c.conn.QueryRow(ctx, query, args...)
	if row == nil {
		return nil
	}
	return &rowAdapter{Row: row}
}

func (c *connWrapper) Select(ctx context.Context, dest interface{}, query string, args ...any) error {
	return c.conn.Select(ctx, dest, query, args...)
}

func (c *connWrapper) Exec(ctx context.Context, query string, args ...any) error {
	return c.conn.Exec(ctx, query, args...)
}

func (c *connWrapper) PrepareBatch(ctx context.Context, query string) (telemetrystore.Batch, error) {
	batch, err := c.conn.PrepareBatch(ctx, query)
	if err != nil {
		return nil, err
	}
	return &batchAdapter{Batch: batch}, nil
}

// NewConnWrapper creates a telemetrystore.Conn wrapper around a clickhouse.Conn.
// Exported for use by test packages.
func NewConnWrapper(conn clickhouse.Conn) telemetrystore.Conn {
	return &connWrapper{conn: conn}
}
