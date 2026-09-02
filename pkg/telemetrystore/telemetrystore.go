package telemetrystore

import (
	"context"
	"reflect"

	"github.com/SigNoz/signoz/pkg/types/telemetrystoretypes"
)

// ColumnType describes a single column returned by a query.
// It abstracts over driver-specific column metadata (e.g. ClickHouse driver.ColumnType).
type ColumnType interface {
	// Name returns the column name.
	Name() string
	// DatabaseTypeName returns the database system name of the column type.
	DatabaseTypeName() string
	// ScanType returns the Go type suitable for scanning into.
	ScanType() reflect.Type
}

// Rows is an interface for iterating over query result rows.
// It is modeled after database/sql.Rows and driver.Rows but is storage-agnostic.
type Rows interface {
	// Next prepares the next result row. It returns false when no more rows are available.
	Next() bool
	// Scan copies the columns in the current row into the values pointed at by dest.
	Scan(dest ...any) error
	// Close closes the Rows, preventing further enumeration.
	Close() error
	// Err returns the error, if any, that was encountered during iteration.
	Err() error
	// Columns returns the column names.
	Columns() ([]string, error)
	// ColumnTypes returns column types for the result set.
	ColumnTypes() ([]ColumnType, error)
}

// Row represents a single row from a query.
type Row interface {
	// Scan copies the columns into the values pointed at by dest.
	Scan(dest ...any) error
	// ScanStruct copies the columns into the struct pointed at by dest.
	ScanStruct(dest any) error
	// Err returns the error, if any, that was encountered while scanning.
	Err() error
}

// Batch represents a batch insert operation.
type Batch interface {
	// Append adds a row to the batch.
	Append(v ...any) error
	// Send flushes the batch to the server.
	Send() error
	// Abort cancels the batch.
	Abort() error
	// Close closes the batch.
	Close() error
}

// Conn is a generic database connection interface abstracting over storage backends.
type Conn interface {
	// Query executes a query that returns multiple rows.
	Query(ctx context.Context, query string, args ...any) (Rows, error)
	// QueryRow executes a query that returns at most one row.
	QueryRow(ctx context.Context, query string, args ...any) Row
	// Select executes a query and scans the results into dest.
	Select(ctx context.Context, dest interface{}, query string, args ...any) error
	// Exec executes a query that doesn't return rows.
	Exec(ctx context.Context, query string, args ...any) error
	// PrepareBatch prepares a batch insert statement.
	PrepareBatch(ctx context.Context, query string) (Batch, error)
}

// TelemetryStore is the interface for telemetry storage backends.
// Implementations must provide DB() for generic query execution.
type TelemetryStore interface {
	// DB returns the generic database connection.
	DB() Conn

	// Cluster returns the cluster name.
	Cluster() string

	// Estimate returns the per-table scan estimate from EXPLAIN ESTIMATE.
	Estimate(ctx context.Context, stmt string, args ...any) ([]telemetrystoretypes.EstimateEntry, error)

	// Plan runs EXPLAIN PLAN to check stmt parses and binds.
	Plan(ctx context.Context, stmt string, args ...any) error

	// Indexes returns the granule-skip breakdown from EXPLAIN json = 1, indexes = 1.
	Indexes(ctx context.Context, stmt string, args ...any) (telemetrystoretypes.Granules, bool, error)
}

type TelemetryStoreHook interface {
	BeforeQuery(ctx context.Context, event *QueryEvent) context.Context
	AfterQuery(ctx context.Context, event *QueryEvent)
}

func WrapBeforeQuery(hooks []TelemetryStoreHook, ctx context.Context, event *QueryEvent) context.Context {
	for _, hook := range hooks {
		ctx = hook.BeforeQuery(ctx, event)
	}
	return ctx
}

func WrapAfterQuery(hooks []TelemetryStoreHook, ctx context.Context, event *QueryEvent) {
	for i := len(hooks) - 1; i >= 0; i-- {
		hooks[i].AfterQuery(ctx, event)
	}
}
