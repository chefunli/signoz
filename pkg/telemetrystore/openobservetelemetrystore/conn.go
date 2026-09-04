package openobservetelemetrystore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SigNoz/signoz/pkg/telemetrystore"
)

// ooConn implements telemetrystore.Conn by sending SQL queries to OpenObserve HTTP API.
type ooConn struct {
	endpoint string
	orgID    string
	username string
	password string
	client   *http.Client
	logger   *slog.Logger
}

func newOOConn(endpoint, orgID, username, password string, logger *slog.Logger) *ooConn {
	return &ooConn{
		endpoint: strings.TrimRight(endpoint, "/"),
		orgID:    orgID,
		username: username,
		password: password,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: logger,
	}
}

// searchRequest is the OpenOberve search API request body.
type searchRequest struct {
	Query searchQuery `json:"query"`
}

type searchQuery struct {
	SQL       string `json:"sql"`
	StartTime int64  `json:"start_time"`
	EndTime   int64  `json:"end_time"`
	From      int    `json:"from"`
	Size      int    `json:"size"`
}

// extractStreamAndTimeRange parses a SQL query to extract the primary stream name and
// attempts to determine time range from WHERE clause.
// It uses mapCHTableToOOStream to resolve ClickHouse table names to OpenObserve streams.
func extractStreamAndTimeRange(query string) (stream string, streamType string, startTime, endTime int64) {
	// Find all FROM clause table references
	fromRe := regexp.MustCompile(`(?i)\bFROM\s+([\w\.]+)`)
	matches := fromRe.FindAllStringSubmatch(query, -1)

	// Try each FROM reference and find the first one that maps to a known stream
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		tableName := m[1]
		// Remove backticks and quotes
		tableName = strings.ReplaceAll(tableName, "`", "")
		tableName = strings.ReplaceAll(tableName, "\"", "")
		// Remove database prefix
		if idx := strings.LastIndex(tableName, "."); idx >= 0 {
			tableName = tableName[idx+1:]
		}
		// Skip if it looks like a subquery alias or is not a real table
		if strings.HasPrefix(tableName, "(") || strings.HasPrefix(strings.ToUpper(tableName), "SELECT") {
			continue
		}
		// Try to map to OpenObserve stream
		sName, sType := mapCHTableToOOStream(tableName)
		if sName != "" {
			stream = sName
			streamType = sType
			break
		}
	}

	// Default time range: last 30 days
	now := time.Now()
	startTime = now.Add(-30 * 24 * time.Hour).UnixMicro()
	endTime = now.Add(24 * time.Hour).UnixMicro()

	// Try to extract time range from WHERE clause
	// Match _timestamp, timestamp, or start_time (after translation) with optional quotes
	startRe := regexp.MustCompile(`(?i)(?:_timestamp|timestamp|start_time)\s*>=\s*['"]?(\d{13,19})['"]?`)
	if m := startRe.FindStringSubmatch(query); len(m) > 1 {
		if v, err := fmt.Sscanf(m[1], "%d", &startTime); v == 1 && err == nil {
			if startTime > 1e18 {
				startTime = startTime / 1000 // nanoseconds → microseconds
			}
		}
	}

	endRe := regexp.MustCompile(`(?i)(?:_timestamp|timestamp|start_time)\s*<\=?\s*['"]?(\d{13,19})['"]?`)
	if m := endRe.FindStringSubmatch(query); len(m) > 1 {
		if v, err := fmt.Sscanf(m[1], "%d", &endTime); v == 1 && err == nil {
			if endTime > 1e18 {
				endTime = endTime / 1000 // nanoseconds → microseconds
			}
		}
	}

	return stream, streamType, startTime, endTime
}

func (c *ooConn) executeQuery(ctx context.Context, query string, args ...any) (*ooResponse, error) {
	// Interpolate args into query
	sql := interpolateArgs(query, args...)

	c.logger.InfoContext(ctx, "openobserve: executeQuery called", "sql_full", sql[:min(len(sql), 500)])

	// Handle SHOW CREATE TABLE specially
	if isShowCreateTable(sql) {
		return c.handleShowCreateTable(ctx, sql)
	}

	// Skip write operations
	trimmed := strings.TrimSpace(sql)
	upper := strings.ToUpper(trimmed)
	for _, prefix := range []string{"CREATE", "INSERT", "ALTER", "DROP", "TRUNCATE", "SET"} {
		if strings.HasPrefix(upper, prefix) {
			c.logger.DebugContext(ctx, "openobserve: skipping write operation", "query_prefix", prefix)
			return &ooResponse{Hits: []map[string]any{}, Total: 0}, nil
		}
	}

	// ---- Intent-based routing ----
	// Instead of translating ClickHouse SQL to OpenObserve SQL,
	// we classify the query intent, build a native OpenObserve query,
	// execute it, and transform the results to match what the caller expects.

	// 1. Dependency graph → compute from raw traces in OpenObserve
	if isDependencyGraphQuery(sql) {
		return c.handleDependencyGraphQuery(ctx, sql, args...)
	}

	// 2. Trace detail queries → query traces directly
	if isTraceDetailQuery(sql) {
		if resp, err := c.handleTraceDetailQuery(ctx, sql, args...); err == nil {
			return resp, nil
		}
		c.logger.ErrorContext(ctx, "openobserve: handleTraceDetailQuery failed, returning empty")
		return &ooResponse{Hits: []map[string]any{}, Total: 0}, nil
	}

	// 3. Services / traces / logs queries via intent classification
	if resp, handled, err := c.handleNativeQuery(ctx, sql); handled {
		return resp, err
	}

	// 4. Field keys metadata queries → synthesize from O2 field discovery
	if isFieldKeysMetadataQuery(sql) {
		c.logger.InfoContext(ctx, "openobserve: routing to handleFieldKeysMetadataQuery")
		resp, err := c.handleFieldKeysMetadataQuery(ctx, sql)
		if err != nil {
			c.logger.ErrorContext(ctx, "openobserve: handleFieldKeysMetadataQuery failed", "error", err.Error())
		} else {
			c.logger.InfoContext(ctx, "openobserve: handleFieldKeysMetadataQuery succeeded", "hits", len(resp.Hits))
		}
		return resp, err
	}

	// 5. ClickHouse-specific tables with no O2 equivalent → return empty
	if isMetricsOnlyQuery(sql) || isTagAttributesQuery(sql) || isAttributeKeysQuery(sql) {
		c.logger.DebugContext(ctx, "openobserve: skipping unsupported query", "sql_preview", sql[:min(len(sql), 100)])
		return &ooResponse{Hits: []map[string]any{}, Total: 0}, nil
	}

	// 6. For all other queries, determine signal type and build a basic O2 query
	c.logger.InfoContext(ctx, "openobserve: falling through to handleGenericQuery", "sql_full", sql[:min(len(sql), 500)])
	return c.handleGenericQuery(ctx, sql, args...)
}

// isShowCreateTable checks if the query is a SHOW CREATE TABLE command.
func isShowCreateTable(sql string) bool {
	upper := strings.ToUpper(strings.TrimSpace(sql))
	return strings.HasPrefix(upper, "SHOW CREATE TABLE")
}

// handleShowCreateTable handles SHOW CREATE TABLE queries.
// It tries to discover fields from OpenObserve by querying a sample row.
// If that fails (stream not found, no data, etc.), it returns a synthetic
// schema based on known field mappings so the querier can continue.
func (c *ooConn) handleShowCreateTable(ctx context.Context, sql string) (*ooResponse, error) {
	parts := strings.Fields(sql)
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid SHOW CREATE TABLE query: %s", sql)
	}
	tableName := parts[3]
	if idx := strings.LastIndex(tableName, "."); idx >= 0 {
		tableName = tableName[idx+1:]
	}
	tableName = strings.ReplaceAll(tableName, "`", "")
	tableName = strings.ReplaceAll(tableName, "\"", "")

	streamName, streamType := mapCHTableToOOStream(tableName)
	if streamName == "" || streamName == "__empty__" {
		// Return a minimal synthetic schema so the querier doesn't fail
		createStmt := fmt.Sprintf("CREATE TABLE %s (\n    `timestamp` Int64\n) ENGINE = MergeTree()", tableName)
		return &ooResponse{Hits: []map[string]any{{"statement": createStmt, "Statement": createStmt}}, Total: 1}, nil
	}

	c.logger.DebugContext(ctx, "openobserve: handling SHOW CREATE TABLE",
		"ch_table", tableName, "oo_stream", streamName, "oo_type", streamType)

	// Try to discover fields from OpenObserve
	columns := c.discoverFieldsFromO2(ctx, streamName, streamType)

	// If discovery returned nothing, use a pre-defined schema
	if len(columns) == 0 {
		columns = getSyntheticSchema(tableName)
	}

	// If still nothing, return a minimal schema
	if len(columns) == 0 {
		columns = []string{"`timestamp` Int64"}
	}

	createStmt := fmt.Sprintf("CREATE TABLE %s (\n%s\n) ENGINE = MergeTree()",
		tableName, strings.Join(columns, ",\n"))

	return &ooResponse{
		Hits:  []map[string]any{{"statement": createStmt, "Statement": createStmt}},
		Total: 1,
	}, nil
}

// discoverFieldsFromO2 queries OpenObserve for a sample row to discover field names.
func (c *ooConn) discoverFieldsFromO2(ctx context.Context, streamName, streamType string) []string {
	now := time.Now()
	sampleQuery := fmt.Sprintf("SELECT * FROM \"%s\" LIMIT 1", streamName)
	reqBody := searchRequest{
		Query: searchQuery{
			SQL:       sampleQuery,
			StartTime: now.Add(-30 * 24 * time.Hour).UnixMicro(),
			EndTime:   now.Add(24 * time.Hour).UnixMicro(),
			From:      0,
			Size:      1,
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil
	}

	url := fmt.Sprintf("%s/api/%s/_search?type=%s", c.endpoint, c.orgID, streamType)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.DebugContext(ctx, "openobserve: field discovery failed", "error", err.Error())
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logger.DebugContext(ctx, "openobserve: field discovery non-200", "status", resp.StatusCode)
		return nil
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var ooResp ooResponse
	if err := json.Unmarshal(respBody, &ooResp); err != nil {
		return nil
	}

	if len(ooResp.Hits) == 0 {
		c.logger.DebugContext(ctx, "openobserve: no sample data for field discovery", "stream", streamName)
		return nil
	}

	var columns []string
	for key, val := range ooResp.Hits[0] {
		colType := inferClickHouseType(val)
		columns = append(columns, fmt.Sprintf("    `%s` %s", key, colType))
	}
	c.logger.DebugContext(ctx, "openobserve: discovered fields from O2",
		"stream", streamName, "field_count", len(columns))
	return columns
}

// getSyntheticSchema returns a pre-defined set of columns for known ClickHouse tables.
// This is used when OpenObserve field discovery fails (no data, stream not found, etc.)
// so that the querier can still generate SQL (which ooConn will handle natively).
func getSyntheticSchema(tableName string) []string {
	lower := strings.ToLower(tableName)
	switch lower {
	case "distributed_signoz_index_v3", "signoz_index_v3", "signoz_index_v2",
		"distributed_signoz_index_v2", "signoz_spans", "distributed_signoz_spans":
		return []string{
			"`timestamp` Int64", "`timestamp` DateTime", "`trace_id` String",
			"`span_id` String", "`parent_span_id` String",
			"`resource_string_service$$name` String", "`name` String",
			"`kind` Int8", "`kind_string` String",
			"`duration_nano` Int64", "`has_error` UInt8",
			"`status_code` Int32", "`status_code_string` String",
			"`status_message` String",
			"`attributes_string` String", "`attributes_number` String", "`attributes_bool` String",
			"`resources_string` String", "`events` String",
			"`response_status_code` Int32",
			"`http_method` String", "`http_url` String", "`http_host` String",
			"`db_name` String", "`db_operation` String",
			"`external_http_method` String", "`external_http_url` String",
			"`links` String", "`flags` Int64", "`trace_state` String", "`is_remote` String",
			"`ts_bucket_start` Int64",
		}
	case "distributed_logs_v2", "logs_v2", "distributed_logs", "logs":
		return []string{
			"`timestamp` Int64", "`id` String", "`trace_id` String", "`span_id` String",
			"`trace_flags` Int32", "`severity_text` String", "`severity_number` Int32",
			"`body` String", "`service_name` String",
			"`attributes_string` String", "`attributes_number` String", "`attributes_bool` String",
			"`resources_string` String",
			"`ts_bucket_start` Int64",
		}
	case "distributed_dependency_graph_minutes_v2", "dependency_graph_minutes_v2":
		return []string{
			"`timestamp` DateTime", "`src` String", "`dest` String",
			"`total_count` UInt64", "`error_count` UInt64",
			"`duration_quantiles_state` String", "`is_pre_aggregated` UInt8",
		}
	case "distributed_top_level_operations", "top_level_operations":
		return []string{
			"`name` String", "`serviceName` String", "`time` Int64",
		}
	default:
		return nil
	}
}

// mapCHTableToOOStream maps ClickHouse table names used by SigNoz to
// OpenObserve stream names and stream types.
func mapCHTableToOOStream(chTable string) (streamName string, streamType string) {
	switch strings.ToLower(chTable) {
	// Traces
	case "distributed_signoz_index_v3", "signoz_index_v3", "signoz_index_v2",
		"distributed_signoz_index_v2", "signoz_spans", "distributed_signoz_spans",
		"distributed_trace_summary", "trace_summary":
		return "default", "traces"

	// Logs — OpenObserve uses "default" stream with type "logs"
	case "distributed_logs_v2", "logs_v2", "distributed_logs", "logs":
		return "default", "logs"

	// Log attribute/resource keys
	case "distributed_log_attribute_keys", "log_attribute_keys":
		return "default", "logs"
	case "distributed_log_resource_keys", "log_resource_keys":
		return "default", "logs"

	// Span attributes
	case "distributed_span_attributes_keys", "span_attributes_keys":
		return "default", "traces"

	// Tag attributes (used by services/metrics queries)
	case "distributed_tag_attributes_v2", "tag_attributes_v2",
		"distributed_tag_attributes", "tag_attributes":
		return "default", "traces"

	// Metadata tables — no equivalent in OpenObserve, return empty results
	case "distributed_metadata", "metadata",
		"distributed_column_evolution_metadata", "column_evolution_metadata":
		return "__empty__", "logs"

	// Audit logs
	case "distributed_audit_logs", "audit_logs":
		return "default", "logs"

	// Metrics
	case "distributed_samples_v2", "samples_v2", "distributed_samples", "samples":
		return "", ""
	case "distributed_time_series_v2", "time_series_v2":
		return "", ""
	case "distributed_time_series_v4_1day", "time_series_v4_1day":
		return "", ""
	case "distributed_time_series_v4_6hr", "time_series_v4_6hr":
		return "", ""
	case "distributed_time_series_v4_1day_agg", "time_series_v4_1day_agg":
		return "", ""
	case "distributed_updated_metadata", "updated_metadata":
		return "", ""

	default:
		// Try using the table name directly as the stream name
		return chTable, "logs"
	}
}

// inferClickHouseType infers a ClickHouse column type from a Go value.
func inferClickHouseType(val any) string {
	switch v := val.(type) {
	case float64:
		if v == float64(int64(v)) {
			return "Int64"
		}
		return "Float64"
	case bool:
		return "UInt8"
	case string:
		return "String"
	case []any:
		if len(v) > 0 {
			return "Array(" + inferClickHouseType(v[0]) + ")"
		}
		return "Array(String)"
	case map[string]any:
		return "String" // JSON objects mapped to String for simplicity
	default:
		return "String"
	}
}

func (c *ooConn) Query(ctx context.Context, query string, args ...any) (telemetrystore.Rows, error) {
	resp, err := c.executeQuery(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	// If the handler didn't set columnOrder, extract it from the SQL so that
	// Scan sees columns in the order the caller expects.
	if len(resp.columnOrder) == 0 && len(resp.Hits) > 0 {
		resp.columnOrder = extractColumnOrderFromSQL(query)
	}
	rows := newOORows(resp)
	c.logger.DebugContext(ctx, "ooConn.Query result",
		"hits", len(resp.Hits), "columns", rows.columns, "columnOrder", resp.columnOrder)
	return rows, nil
}

func (c *ooConn) QueryRow(ctx context.Context, query string, args ...any) telemetrystore.Row {
	resp, err := c.executeQuery(ctx, query, args...)
	if err != nil {
		return &ooRow{err: err}
	}
	if len(resp.Hits) == 0 {
		return &ooRow{err: sql.ErrNoRows}
	}
	return newOORowWithOrder(resp.Hits[0], resp.columnOrder)
}

func (c *ooConn) Select(ctx context.Context, dest interface{}, query string, args ...any) error {
	resp, err := c.executeQuery(ctx, query, args...)
	if err != nil {
		return err
	}

	// OpenObserve lowercases all SQL aliases in response keys.
	// Normalize hit keys to match the destination struct's JSON tags
	// (e.g. "servicename" → "serviceName") so json.Unmarshal can match them.
	normalizeHitKeys(resp.Hits, dest)

	// Convert string values that are JSON objects/arrays to actual maps/slices.
	// OpenObserve returns '{}' as a string, but Go structs expect map[string]T.
	coerceHitStringsToJSON(resp.Hits, dest)

	// Use JSON round-trip to unmarshal hits into dest
	data, err := json.Marshal(resp.Hits)
	if err != nil {
		return fmt.Errorf("marshal hits: %w", err)
	}
	if err := json.Unmarshal(data, dest); err != nil {
		c.logger.ErrorContext(ctx, "openobserve: Select json.Unmarshal failed",
			"error", err.Error(),
			"dest_type", fmt.Sprintf("%T", dest),
			"hits_count", len(resp.Hits),
			"json_preview", string(data[:min(len(data), 500)]))
		return fmt.Errorf("unmarshal hits into %T: %w", dest, err)
	}
	return nil
}

func (c *ooConn) Exec(ctx context.Context, query string, args ...any) error {
	// OpenObserve handles its own data ingestion via OTLP.
	// DDL/DML operations are no-ops.
	trimmed := strings.TrimSpace(query)
	upper := strings.ToUpper(trimmed)
	for _, prefix := range []string{"CREATE", "INSERT", "ALTER", "DROP", "TRUNCATE", "SET"} {
		if strings.HasPrefix(upper, prefix) {
			c.logger.DebugContext(ctx, "openobserve: skipping write operation", "query_prefix", prefix)
			return nil
		}
	}
	// For other queries, still execute them
	_, err := c.executeQuery(ctx, query, args...)
	return err
}

func (c *ooConn) PrepareBatch(ctx context.Context, query string) (telemetrystore.Batch, error) {
	// OpenObserve handles ingestion via OTLP; batch inserts are no-ops.
	return &ooBatch{}, nil
}

// Ensure ooConn satisfies the interface at compile time.
var _ telemetrystore.Conn = (*ooConn)(nil)

// isTagAttributesQuery detects ClickHouse tag_attributes queries that reference
// fields like tagKey, tagType, isColumn, dataType which don't exist in OpenObserve.
// Also detects field value/autocomplete queries that reference tag_key, string_value etc.
func isTagAttributesQuery(sql string) bool {
	lower := strings.ToLower(sql)
	// These queries typically SELECT tagKey, tagType, dataType … WHERE isColumn = …
	if (strings.Contains(lower, "tagkey") || strings.Contains(lower, "tagtype")) &&
		strings.Contains(lower, "iscolumn") {
		return true
	}
	// Field value queries: SELECT ... FROM tag_attributes WHERE tag_key = ...
	// These reference tag_key, string_value, number_value which don't exist in O2 traces
	if strings.Contains(lower, "tag_key") &&
		(strings.Contains(lower, "string_value") || strings.Contains(lower, "number_value")) {
		return true
	}
	// Also catch queries against tag_attributes table directly
	if strings.Contains(lower, "tag_attributes") {
		return true
	}
	// Metadata key queries: SELECT tag_key, tag_type, tag_data_type ... FROM signoz_logs.*
	// These are used by GetKeys/GetFieldsKeys to discover available field keys.
	if strings.Contains(lower, "tag_data_type") && strings.Contains(lower, "tag_key") &&
		strings.Contains(lower, "tag_type") {
		return true
	}
	return false
}

// isMetricsOnlyQuery detects queries that reference ClickHouse metrics tables
// that have no OpenObserve equivalent.
func isMetricsOnlyQuery(sql string) bool {
	lower := strings.ToLower(sql)
	metricsTables := []string{
		"samples_v2", "samples",
		"time_series_v2", "time_series_v4",
		"distributed_samples", "distributed_time_series",
		"updated_metadata",
	}
	for _, t := range metricsTables {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// isAttributeKeysQuery detects queries against ClickHouse internal attribute/resource
// key tables (e.g. distributed_logs_attribute_keys) that don't exist in OpenObserve.
func isAttributeKeysQuery(sql string) bool {
	lower := strings.ToLower(sql)
	// Match known ClickHouse internal key-table names
	internalTables := []string{
		// Logs attribute/resource key tables
		"distributed_logs_attribute_keys",
		"logs_attribute_keys",
		"distributed_logs_resource_keys",
		"logs_resource_keys",
		// Traces attribute key tables
		"distributed_span_attributes_keys",
		"span_attributes_keys",
		"distributed_traces_attribute_keys",
		"traces_attribute_keys",
		// Column evolution metadata
		"column_evolution_metadata",
		"distributed_column_evolution_metadata",
	}
	for _, t := range internalTables {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// isTraceDetailQuery detects SQL queries from the traceStore module that need
// ClickHouse-specific syntax translation (DISTINCT ON, ts_bucket_start, trace_summary, etc.).
func isTraceDetailQuery(sql string) bool {
	lower := strings.ToLower(sql)
	// Must reference signoz_traces tables (not v3 queries which use __SELECT_KEY_ aliases)
	if !strings.Contains(lower, "signoz_traces") {
		return false
	}
	return strings.Contains(lower, "trace_summary") ||
		strings.Contains(lower, "distinct on (span_id)") ||
		(strings.Contains(lower, "any(parent_span_id)") && strings.Contains(lower, "signoz_index_v3"))
}

// translateTraceDetailSQL translates ClickHouse trace detail SQL to OpenObserve-compatible SQL.
// This handles queries from the traceStore module that use ClickHouse-specific syntax.
//
// The key challenge is that field replacements (e.g. timestamp → _timestamp AS timestamp)
// produce aliases that are only valid in SELECT clauses. In WHERE/ORDER BY/GROUP BY, these
// aliases produce invalid SQL. Additionally, alias names can cascade (e.g. the "name" in
// "resource_string_service$$name" alias gets matched by the "name" regex).
//
// Solution: Split SQL at FROM keyword. Apply full alias-producing replacements only to the
// SELECT clause. Apply simple name-only translations to the rest (WHERE/ORDER BY/GROUP BY).
func translateTraceDetailSQL(query string) string {
	sql := query

	// --- Step 1: Trace summary specific translations ---
	if strings.Contains(strings.ToLower(sql), "trace_summary") {
		sql = regexp.MustCompile(`(?i)\bmin\(start\)\s+AS\s+start\b`).ReplaceAllString(sql, "MIN(_timestamp) AS start")
		sql = regexp.MustCompile(`(?i)\bmax\(end\)\s+AS\s+end\b`).ReplaceAllString(sql, "MAX(_timestamp + duration / 1000) AS end")
		sql = regexp.MustCompile(`(?i)\bsum\(num_spans\)\s+AS\s+num_spans\b`).ReplaceAllString(sql, "COUNT(*) AS num_spans")
	}

	// --- Step 2: Remove ClickHouse-specific syntax ---
	sql = regexp.MustCompile(`(?i)\bDISTINCT\s+ON\s*\([^)]+\)\s*`).ReplaceAllString(sql, "")
	// ts_bucket_start conditions → remove with surrounding AND
	sql = regexp.MustCompile(`(?i)\s+AND\s+ts_bucket_start\s*(?:>=|<=)\s*[^\s]+`).ReplaceAllString(sql, "")
	sql = regexp.MustCompile(`(?i)ts_bucket_start\s*(?:>=|<=)\s*[^\s]+\s+AND\s+`).ReplaceAllString(sql, "")
	sql = regexp.MustCompile(`(?i)\bWHERE\s+AND\b`).ReplaceAllString(sql, "WHERE")
	sql = regexp.MustCompile(`(?i)\bAND\s+AND\b`).ReplaceAllString(sql, "AND")

	// --- Step 3: Split SQL at FROM keyword ---
	// SELECT clause gets full alias-producing replacements.
	// Everything after FROM (WHERE/ORDER BY/GROUP BY) gets simple name-only translations.
	fromIdx := regexp.MustCompile(`(?i)\s+FROM\s+`).FindStringIndex(sql)
	if fromIdx == nil {
		// No FROM found — apply SELECT replacements to entire SQL
		sql = applySelectReplacements(sql)
	} else {
		selectClause := sql[:fromIdx[0]]
		restClause := sql[fromIdx[0]:]
		selectClause = applySelectReplacements(selectClause)
		restClause = applyNonSelectTranslations(restClause)
		sql = selectClause + restClause
	}

	// --- Step 4: Rewrite table references ---
	sql = regexp.MustCompile(`(?i)signoz_traces\.distributed_signoz_index_v3`).ReplaceAllString(sql, `"default"`)
	sql = regexp.MustCompile(`(?i)signoz_traces\.distributed_trace_summary`).ReplaceAllString(sql, `"default"`)
	sql = regexp.MustCompile(`(?i)\bdistributed_signoz_index_v3\b`).ReplaceAllString(sql, `"default"`)
	sql = regexp.MustCompile(`(?i)\bdistributed_trace_summary\b`).ReplaceAllString(sql, `"default"`)

	return sql
}

// applySelectReplacements applies field name translations with aliases for SELECT clauses.
// These produce expressions like "_timestamp AS timestamp" which are only valid in SELECT.
func applySelectReplacements(sql string) string {
	// Translate any() → MIN()
	sql = regexp.MustCompile(`(?i)\bany\(`).ReplaceAllString(sql, "MIN(")

	// --- Phase 1: Translate field names INSIDE function arguments only ---
	// Match MIN(field) and translate the field inside, preserving the alias.
	// E.g. MIN(parent_span_id) AS parent_span_id → MIN(reference_parent_span_id) AS parent_span_id
	translateFuncArg := func(pattern, replacement string) {
		re := regexp.MustCompile(`(?i)(MIN\s*\()\s*` + pattern + `\s*(\))`)
		sql = re.ReplaceAllString(sql, "${1}"+replacement+"${2}")
	}
	translateFuncArg(`(?i)resource_string_service\$\$name`, `service_name`)
	translateFuncArg(`timestamp`, `_timestamp`)
	translateFuncArg(`duration_nano`, `(duration * 1000)`)
	translateFuncArg(`has_error`, `(CASE WHEN status_code = 2 THEN 1 ELSE 0 END)`)
	translateFuncArg(`(?i)parent_span_id`, `reference_parent_span_id`)
	translateFuncArg(`name`, `operation_name`)
	translateFuncArg(`kind`, `span_kind`)
	translateFuncArg(`attributes_string`, `'{}'`)
	translateFuncArg(`attributes_number`, `'{}'`)
	translateFuncArg(`attributes_bool`, `'{}'`)
	translateFuncArg(`resources_string`, `'{}'`)
	translateFuncArg(`events`, `events`)

	// --- Phase 2: Protect func(expr) AS alias patterns ---
	var protected []string
	sql = regexp.MustCompile(`(?i)(\w+\([^)]*\)[^\S\n]*AS[^\S\n]+\w+)`).ReplaceAllStringFunc(sql, func(match string) string {
		idx := len(protected)
		protected = append(protected, match)
		return fmt.Sprintf("__PROT%d__", idx)
	})

	// --- Phase 3: Add aliases for remaining standalone field names ---
	sql = regexp.MustCompile(`(^|[^_\w])\btimestamp\b`).ReplaceAllString(sql, "${1}_timestamp AS timestamp")
	sql = regexp.MustCompile(`\bduration_nano\b`).ReplaceAllString(sql, "(duration * 1000) AS duration_nano")
	sql = regexp.MustCompile(`\bhas_error\b`).ReplaceAllString(sql, "(CASE WHEN status_code = 2 THEN 1 ELSE 0 END) AS has_error")
	sql = regexp.MustCompile(`(?i)resource_string_service\$\$name`).ReplaceAllString(sql, "service_name AS __SVCSVC__")
	sql = regexp.MustCompile(`(^|[^_\w])\bname\b`).ReplaceAllString(sql, "${1}operation_name AS name")
	sql = regexp.MustCompile(`(?i)\bparent_span_id\b`).ReplaceAllString(sql, "reference_parent_span_id AS __SPSID__")
	sql = regexp.MustCompile(`\bkind_string\b`).ReplaceAllString(sql, "span_kind AS kind_string")
	sql = regexp.MustCompile(`\bkind\b`).ReplaceAllString(sql, "span_kind AS kind")
	sql = regexp.MustCompile(`\battributes_string\b`).ReplaceAllString(sql, "'{}' AS attributes_string")
	sql = regexp.MustCompile(`\battributes_number\b`).ReplaceAllString(sql, "'{}' AS attributes_number")
	sql = regexp.MustCompile(`\battributes_bool\b`).ReplaceAllString(sql, "'{}' AS attributes_bool")
	sql = regexp.MustCompile(`\bresources_string\b`).ReplaceAllString(sql, "'{}' AS resources_string")
	sql = regexp.MustCompile(`\bresponse_status_code\b`).ReplaceAllString(sql, "http_status_code AS response_status_code")
	sql = regexp.MustCompile(`\bdb_name\b`).ReplaceAllString(sql, "'' AS db_name")
	sql = regexp.MustCompile(`\bdb_operation\b`).ReplaceAllString(sql, "'' AS db_operation")
	sql = regexp.MustCompile(`\bexternal_http_method\b`).ReplaceAllString(sql, "'' AS external_http_method")
	sql = regexp.MustCompile(`\bexternal_http_url\b`).ReplaceAllString(sql, "'' AS external_http_url")
	sql = regexp.MustCompile(`\bhttp_host\b`).ReplaceAllString(sql, "'' AS http_host")
	sql = regexp.MustCompile(`\btrace_state\b`).ReplaceAllString(sql, "'' AS trace_state")
	sql = regexp.MustCompile(`\bflags\b`).ReplaceAllString(sql, "0 AS flags")
	sql = regexp.MustCompile(`\bis_remote\b`).ReplaceAllString(sql, "'' AS is_remote")
	sql = regexp.MustCompile(`\bstatus_code_string\b`).ReplaceAllString(sql,
		"(CASE WHEN status_code = 1 THEN 'OK' WHEN status_code = 2 THEN 'ERROR' ELSE 'UNSET' END) AS status_code_string")
	sql = regexp.MustCompile(`\blinks\b(?!\s+as\s+\w+)(?:\s+as\s+\w+)?`).ReplaceAllString(sql, "links AS references")

	// Restore placeholders
	sql = strings.ReplaceAll(sql, "__SVCSVC__", "resource_string_service$$name")
	sql = strings.ReplaceAll(sql, "__SPSID__", "parent_span_id")

	// Restore protected expressions
	for i, expr := range protected {
		sql = strings.Replace(sql, fmt.Sprintf("__PROT%d__", i), expr, 1)
	}

	return sql
}

// applyNonSelectTranslations applies simple name-only translations for WHERE/ORDER BY/GROUP BY.
// No aliases are produced — only the actual column names used in OpenObserve.
func applyNonSelectTranslations(sql string) string {
	sql = regexp.MustCompile(`(^|[^_\w])\btimestamp\b`).ReplaceAllString(sql, "${1}_timestamp")
	sql = regexp.MustCompile(`\bduration_nano\b`).ReplaceAllString(sql, "(duration * 1000)")
	sql = regexp.MustCompile(`\bhas_error\b`).ReplaceAllString(sql, "(CASE WHEN status_code = 2 THEN 1 ELSE 0 END)")
	sql = regexp.MustCompile(`(?i)resource_string_service\$\$name`).ReplaceAllString(sql, "service_name")
	sql = regexp.MustCompile(`(^|[^_\w])\bname\b`).ReplaceAllString(sql, "${1}operation_name")
	sql = regexp.MustCompile(`(?i)\bparent_span_id\b`).ReplaceAllString(sql, "reference_parent_span_id")
	sql = regexp.MustCompile(`\bkind_string\b`).ReplaceAllString(sql, "span_kind")
	sql = regexp.MustCompile(`\bkind\b`).ReplaceAllString(sql, "span_kind")
	sql = regexp.MustCompile(`\bresponse_status_code\b`).ReplaceAllString(sql, "http_status_code")
	sql = regexp.MustCompile(`\bstatus_code_string\b`).ReplaceAllString(sql, "status_code")
	// These fields don't exist in OpenObserve — map to safe defaults
	sql = regexp.MustCompile(`\battributes_string\b`).ReplaceAllString(sql, "'{}'")
	sql = regexp.MustCompile(`\battributes_number\b`).ReplaceAllString(sql, "'{}'")
	sql = regexp.MustCompile(`\battributes_bool\b`).ReplaceAllString(sql, "'{}'")
	sql = regexp.MustCompile(`\bresources_string\b`).ReplaceAllString(sql, "'{}'")
	sql = regexp.MustCompile(`\bdb_name\b`).ReplaceAllString(sql, "''")
	sql = regexp.MustCompile(`\bdb_operation\b`).ReplaceAllString(sql, "''")
	sql = regexp.MustCompile(`\bexternal_http_method\b`).ReplaceAllString(sql, "''")
	sql = regexp.MustCompile(`\bexternal_http_url\b`).ReplaceAllString(sql, "''")
	sql = regexp.MustCompile(`\bhttp_host\b`).ReplaceAllString(sql, "''")
	sql = regexp.MustCompile(`\btrace_state\b`).ReplaceAllString(sql, "''")
	sql = regexp.MustCompile(`\bflags\b`).ReplaceAllString(sql, "0")
	sql = regexp.MustCompile(`\bis_remote\b`).ReplaceAllString(sql, "''")
	sql = regexp.MustCompile(`\blinks\b`).ReplaceAllString(sql, "references")
	return sql
}

// handleTraceDetailQuery handles trace detail queries (flamegraph, waterfall, trace summary)
// by querying OpenObserve natively and mapping the response fields to StorableSpan column names.
// This avoids the fragile ClickHouse SQL → OpenObserve SQL translation approach.
func (c *ooConn) handleTraceDetailQuery(ctx context.Context, originalSQL string, args ...any) (*ooResponse, error) {
	lower := strings.ToLower(originalSQL)

	// Extract trace_id from SQL literal or from query args
	traceID := ""
	traceIDRe := regexp.MustCompile(`(?i)trace_id\s*=\s*'([^']+)'`)
	if m := traceIDRe.FindStringSubmatch(originalSQL); len(m) >= 2 {
		traceID = m[1]
	} else {
		// Parameterized query: trace_id = ? — find its placeholder index
		traceID = extractParamTraceID(originalSQL, args)
	}
	if traceID == "" {
		return nil, fmt.Errorf("cannot extract trace_id from SQL or args")
	}

	c.logger.DebugContext(ctx, "openobserve: handling trace detail query",
		"trace_id", traceID, "is_trace_summary", strings.Contains(lower, "trace_summary"),
		"sql_preview", originalSQL[:min(len(originalSQL), 300)], "args_count", len(args), "args", args)

	// Query OpenObserve natively — get ALL spans for this trace
	nativeSQL := fmt.Sprintf(`SELECT * FROM "default" WHERE trace_id = '%s' ORDER BY start_time ASC`, traceID)
	resp, err := c.executeOpenObserveQuery(ctx, "default", "traces", nativeSQL)
	if err != nil {
		return nil, fmt.Errorf("query OpenObserve: %w", err)
	}
	if len(resp.Hits) == 0 {
		return &ooResponse{Hits: []map[string]any{}, Total: 0}, nil
	}

	// Check if this is a trace_summary query (aggregated stats)
	if strings.Contains(lower, "trace_summary") {
		return c.buildTraceSummaryResponse(resp.Hits, traceID), nil
	}

	// Map OpenObserve spans to StorableSpan column format
	hits := make([]map[string]any, 0, len(resp.Hits))
	for _, span := range resp.Hits {
		hits = append(hits, mapOOSpanToStorableSpan(span))
	}

	// Extract column order from the original SQL so the scan code can map correctly
	columnOrder := extractColumnOrderFromSQL(originalSQL)

	c.logger.DebugContext(ctx, "openobserve: trace detail query completed",
		"trace_id", traceID, "span_count", len(hits), "column_order", columnOrder)

	return &ooResponse{
		Hits:        hits,
		Total:       len(hits),
		columnOrder: columnOrder,
	}, nil
}

// buildTraceSummaryResponse computes trace summary (start, end, num_spans) from raw spans.
func (c *ooConn) buildTraceSummaryResponse(spans []map[string]any, traceID string) *ooResponse {
	var minStart, maxEnd int64
	minStart = math.MaxInt64
	maxEnd = 0

	for _, span := range spans {
		if st, ok := toInt64Safe(span["start_time"]); ok && st < minStart {
			minStart = st
		}
		if et, ok := toInt64Safe(span["end_time"]); ok && et > maxEnd {
			maxEnd = et
		}
	}
	if minStart == math.MaxInt64 {
		minStart = 0
	}

	hit := map[string]any{
		"trace_id":  traceID,
		"start":     minStart,
		"end":       maxEnd,
		"num_spans": len(spans),
	}
	return &ooResponse{
		Hits:        []map[string]any{hit},
		Total:       1,
		columnOrder: []string{"trace_id", "start", "end", "num_spans"},
	}
}

// mapOOSpanToStorableSpan maps an OpenObserve span to the column names expected by StorableSpan's ch: tags.
func mapOOSpanToStorableSpan(span map[string]any) map[string]any {
	hit := make(map[string]any)

	// timestamp → start_time (OpenObserve start_time is nanoseconds)
	hit["timestamp"] = span["start_time"]

	// duration_nano → duration * 1000 (OpenObserve duration is microseconds, StorableSpan expects nanoseconds)
	if dur, ok := toInt64Safe(span["duration"]); ok {
		hit["duration_nano"] = dur * 1000
	} else {
		hit["duration_nano"] = int64(0)
	}

	hit["span_id"] = getString(span, "span_id")

	// has_error → derive from status_code (2 = ERROR in OpenTelemetry)
	if sc, ok := toInt64Safe(span["status_code"]); ok {
		hit["has_error"] = sc == 2
	} else {
		hit["has_error"] = false
	}

	// kind → span_kind as int8
	if sk, ok := toInt64Safe(span["span_kind"]); ok {
		hit["kind"] = sk
	} else {
		hit["kind"] = int64(0)
	}

	hit["resource_string_service$$name"] = getString(span, "service_name")
	hit["name"] = getString(span, "operation_name")

	// Map attributes — OpenObserve may not have these as separate columns
	hit["attributes_string"] = getMapOrEmpty(span, "attributes_string")
	hit["attributes_number"] = getMapOrEmpty(span, "attributes_number")
	hit["attributes_bool"] = getMapOrEmpty(span, "attributes_bool")
	hit["resources_string"] = getMapOrEmpty(span, "resources_string")

	hit["events"] = convertEventsToStringSlice(span["events"])
	hit["status_message"] = getString(span, "status_message")

	// status_code_string → derive from status_code
	if sc, ok := toInt64Safe(span["status_code"]); ok {
		switch sc {
		case 1:
			hit["status_code_string"] = "OK"
		case 2:
			hit["status_code_string"] = "ERROR"
		default:
			hit["status_code_string"] = "UNSET"
		}
	} else {
		hit["status_code_string"] = "UNSET"
	}

	// kind_string → derive from span_kind
	if sk, ok := toInt64Safe(span["span_kind"]); ok {
		switch sk {
		case 1:
			hit["kind_string"] = "CLIENT"
		case 2:
			hit["kind_string"] = "SERVER"
		case 3:
			hit["kind_string"] = "PRODUCER"
		case 4:
			hit["kind_string"] = "CONSUMER"
		default:
			hit["kind_string"] = "INTERNAL"
		}
	} else {
		hit["kind_string"] = "INTERNAL"
	}

	hit["parent_span_id"] = getString(span, "reference_parent_span_id")

	// flags
	if f, ok := toInt64Safe(span["flags"]); ok {
		hit["flags"] = f
	} else {
		hit["flags"] = int64(0)
	}

	hit["is_remote"] = ""
	hit["trace_state"] = ""

	// status_code
	if sc, ok := toInt64Safe(span["status_code"]); ok {
		hit["status_code"] = sc
	} else {
		hit["status_code"] = int64(0)
	}

	// Fields not available in OpenObserve — use empty defaults
	hit["db_name"] = ""
	hit["db_operation"] = getString(span, "db_system")
	hit["http_method"] = getString(span, "http_method")
	hit["http_url"] = getString(span, "http_url")
	hit["http_host"] = ""
	hit["external_http_method"] = ""
	hit["external_http_url"] = ""
	hit["response_status_code"] = getString(span, "http_status_code")
	hit["references"] = getString(span, "links")

	return hit
}

// Helper functions for safe type conversions

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case float64:
			return fmt.Sprintf("%v", val)
		case nil:
			return ""
		default:
			return fmt.Sprintf("%v", val)
		}
	}
	return ""
}

func getMapOrEmpty(m map[string]any, key string) map[string]any {
	if v, ok := m[key]; ok {
		if mp, ok := v.(map[string]any); ok {
			return mp
		}
	}
	return make(map[string]any)
}

// convertEventsToStringSlice converts OpenObserve events to []string format
// expected by StorableSpan.Events (ClickHouse Array(String)).
// In ClickHouse, events is Array(String) where each element is a JSON-encoded event.
// In OpenObserve, events may be a JSON string like "[]" or "[{...}]",
// or it may already be a parsed []any from JSON decoding.
func convertEventsToStringSlice(v any) []string {
	if v == nil {
		return []string{}
	}
	switch val := v.(type) {
	case string:
		trimmed := strings.TrimSpace(val)
		if trimmed == "" || trimmed == "null" {
			return []string{}
		}
		// Parse the JSON array string
		var events []any
		if err := json.Unmarshal([]byte(trimmed), &events); err != nil {
			// Not valid JSON array — wrap as single element if non-empty
			if trimmed != "[]" {
				return []string{trimmed}
			}
			return []string{}
		}
		return anySliceToEventStrings(events)
	case []any:
		return anySliceToEventStrings(val)
	case []string:
		return val
	default:
		return []string{}
	}
}

// anySliceToEventStrings re-encodes each element of a []any as a JSON string,
// producing the []string format that ClickHouse Array(String) would yield.
func anySliceToEventStrings(events []any) []string {
	result := make([]string, 0, len(events))
	for _, e := range events {
		switch ev := e.(type) {
		case string:
			result = append(result, ev)
		case map[string]any:
			if b, err := json.Marshal(ev); err == nil {
				result = append(result, string(b))
			}
		default:
			if b, err := json.Marshal(ev); err == nil {
				result = append(result, string(b))
			}
		}
	}
	return result
}

func toInt64Safe(v any) (int64, bool) {
	if v == nil {
		return 0, false
	}
	switch val := v.(type) {
	case int64:
		return val, true
	case float64:
		return int64(val), true
	case int:
		return int64(val), true
	case string:
		if n, err := strconv.ParseInt(val, 10, 64); err == nil {
			return n, true
		}
		if f, err := strconv.ParseFloat(val, 64); err == nil {
			return int64(f), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// extractParamTraceID finds the trace_id value from parameterized SQL (trace_id = ?).
// It counts the ? placeholders before the trace_id = ? occurrence to determine the arg index.
func extractParamTraceID(sql string, args []any) string {
	lower := strings.ToLower(sql)
	idx := strings.Index(lower, "trace_id")
	if idx < 0 {
		return ""
	}
	// Count ? placeholders before this position
	argIdx := strings.Count(sql[:idx], "?")
	if argIdx < len(args) {
		switch v := args[argIdx].(type) {
		case string:
			return v
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}

// isDependencyGraphQuery detects dependency graph queries.
func isDependencyGraphQuery(sql string) bool {
	lower := strings.ToLower(sql)
	return strings.Contains(lower, "dependency_graph")
}

// handleDependencyGraphQuery computes a dependency graph from raw traces in OpenObserve.
// The ClickHouse version uses pre-computed data in dependency_graph_minutes_v2.
// We compute it on-the-fly from traces and return results in the same format.
func (c *ooConn) handleDependencyGraphQuery(ctx context.Context, originalSQL string, args ...any) (*ooResponse, error) {
	// Extract time range from SQL args
	startMicro, endMicro := extractTimeRange(originalSQL)

	// Fallback: if times look like seconds, convert to microseconds
	if startMicro > 0 && startMicro < 1e12 {
		startMicro = startMicro * 1e6
	}
	if endMicro > 0 && endMicro < 1e12 {
		endMicro = endMicro * 1e6
	}
	if startMicro > 1e15 {
		startMicro = startMicro / 1000
	}
	if endMicro > 1e15 {
		endMicro = endMicro / 1000
	}
	if startMicro <= 0 || endMicro <= 0 || startMicro >= endMicro {
		now := time.Now().UnixMicro()
		startMicro = now - 30*60*1e6
		endMicro = now
	}

	durationSec := (endMicro - startMicro) / 1e6
	if durationSec <= 0 {
		durationSec = 1
	}

	// Build native O2 query: compute service dependencies from raw traces
	// Result format matches model.ServiceMapDependencyResponseItem:
	//   parent, child, callCount, callRate, errorRate, p50, p75, p90, p95, p99
	nativeSQL := fmt.Sprintf(
		`SELECT
			service_name as "parent",
			service_name as "child",
			COUNT(*) as "callCount",
			CAST(COUNT(*) AS DOUBLE) / %d as "callRate",
			CAST(SUM(CASE WHEN status_code = 2 THEN 1 ELSE 0 END) AS DOUBLE) / COUNT(*) * 100 as "errorRate",
			PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY duration * 1000) as "p50",
			PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY duration * 1000) as "p75",
			PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY duration * 1000) as "p90",
			PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration * 1000) as "p95",
			PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration * 1000) as "p99"
		FROM "default"
		WHERE _timestamp >= %d AND _timestamp <= %d
		GROUP BY service_name`,
		durationSec, startMicro, endMicro,
	)

	c.logger.DebugContext(ctx, "openobserve: computing dependency graph from traces",
		"start", startMicro, "end", endMicro, "duration_sec", durationSec)

	resp, err := c.executeOpenObserveQuery(ctx, "default", "traces", nativeSQL)
	if err != nil {
		c.logger.WarnContext(ctx, "openobserve: dependency graph query failed", "error", err.Error())
		return &ooResponse{Hits: []map[string]any{}, Total: 0}, nil
	}

	return resp, nil
}

// handleGenericQuery is the fallback for queries that don't match any known intent.
// Instead of returning empty results, it attempts to:
// 1. Determine the signal type (traces/logs) from the SQL
// 2. Translate table references and field names to OpenObserve equivalents
// 3. Execute the translated query against OpenObserve
// 4. Return the raw results so the caller can scan them
func (c *ooConn) handleGenericQuery(ctx context.Context, sql string, args ...any) (*ooResponse, error) {
	c.logger.DebugContext(ctx, "openobserve: handleGenericQuery fallback",
		"sql_preview", sql[:min(len(sql), 300)])

	// Determine signal type from SQL content
	stream, streamType, _, _ := extractStreamAndTimeRange(sql)

	if stream == "__empty__" {
		return &ooResponse{Hits: []map[string]any{}, Total: 0}, nil
	}

	// Determine stream type from table references
	if streamType == "" {
		if isTracesSQL(sql) {
			streamType = "traces"
			if stream == "" {
				stream = "default"
			}
		} else if isLogsSQL(sql) {
			streamType = "logs"
			if stream == "" {
				stream = "default"
			}
		} else {
			// Unknown signal type — try traces as default
			streamType = "traces"
			if stream == "" {
				stream = "default"
			}
		}
	}

	// For unknown queries that reference ClickHouse-specific tables, return empty
	if isMetricsOnlyQuery(sql) {
		return &ooResponse{Hits: []map[string]any{}, Total: 0}, nil
	}

	// Translate the ClickHouse SQL to OpenObserve-compatible SQL
	translatedSQL := translateClickHouseToOpenObserve(sql)
	// Rewrite table references to the target stream
	translatedSQL = rewriteTableReferences(translatedSQL, stream)

	c.logger.InfoContext(ctx, "openobserve: executing generic query via translation",
		"stream", stream, "type", streamType,
		"original_sql", sql[:min(len(sql), 300)],
		"translated_sql", translatedSQL[:min(len(translatedSQL), 300)])

	resp, err := c.executeOpenObserveQuery(ctx, stream, streamType, translatedSQL)
	if err != nil {
		c.logger.WarnContext(ctx, "openobserve: generic query execution failed", "error", err.Error())
		return &ooResponse{Hits: []map[string]any{}, Total: 0}, nil
	}

	return resp, nil
}

// isTracesSQL detects whether a SQL query is likely a traces query.
func isTracesSQL(sql string) bool {
	lower := strings.ToLower(sql)
	return strings.Contains(lower, "signoz_traces") ||
		strings.Contains(lower, "signoz_index_v3") ||
		strings.Contains(lower, "signoz_index_v2") ||
		strings.Contains(lower, "signoz_spans") ||
		strings.Contains(lower, "trace_summary") ||
		strings.Contains(lower, "span_kind") ||
		strings.Contains(lower, "trace_id") ||
		strings.Contains(lower, "span_id") ||
		(strings.Contains(lower, "service_name") && strings.Contains(lower, "operation_name")) ||
		strings.Contains(lower, "dependency_graph") ||
		strings.Contains(lower, "distributed_signoz")
}

// isLogsSQL detects whether a SQL query is likely a logs query.
func isLogsSQL(sql string) bool {
	lower := strings.ToLower(sql)
	return strings.Contains(lower, "logs_v2") ||
		strings.Contains(lower, "signoz_logs") ||
		strings.Contains(lower, "distributed_logs") ||
		(strings.Contains(lower, "body") && strings.Contains(lower, "severity")) ||
		strings.Contains(lower, "log_attribute")
}

// isFieldKeysMetadataQuery detects queries that fetch field keys metadata
// (tag_key, tag_type, tag_data_type) from signoz_logs/signoz_traces tables.
// These are generated by telemetrymetadata.GetKeys().
func isFieldKeysMetadataQuery(sql string) bool {
	lower := strings.ToLower(sql)
	return strings.Contains(lower, "tag_data_type") &&
		strings.Contains(lower, "tag_key") &&
		strings.Contains(lower, "tag_type") &&
		(strings.Contains(lower, "signoz_logs") || strings.Contains(lower, "signoz_traces") || strings.Contains(lower, "signoz_index"))
}

// handleFieldKeysMetadataQuery synthesizes a field keys response by discovering
// actual fields from OpenObserve.
func (c *ooConn) handleFieldKeysMetadataQuery(ctx context.Context, sql string) (*ooResponse, error) {
	lower := strings.ToLower(sql)

	// Determine signal type
	streamName := "default"
	streamType := "logs"
	if strings.Contains(lower, "signoz_traces") || strings.Contains(lower, "signoz_index") {
		streamType = "traces"
	}

	// Discover fields from OpenObserve
	columns := c.discoverFieldsFromO2(ctx, streamName, streamType)
	if len(columns) == 0 {
		// Fallback to synthetic schema
		columns = c.discoverFieldsFromO2(ctx, streamName, streamType)
	}

	// Build synthetic rows matching the expected output format:
	// tag_key (string), tag_type (string), tag_data_type (string), priority (uint8)
	// NOTE: We intentionally do NOT include intrinsic/calculated span fields
	// (like timestamp, trace_id, span_id, name, duration_nano, etc.) here.
	// Those fields are resolved directly by getColumn via indexV3Columns.
	// Including them with tag_type="tag" would cause MatchingLogicalFields to
	// return unresolvable candidates, breaking ColumnExpressionFor.
	var hits []map[string]any

	// Add discovered fields from O2
	for _, col := range columns {
		col = strings.TrimSpace(col)
		// Parse "`field_name` Type" format
		parts := strings.SplitN(col, " ", 2)
		if len(parts) != 2 {
			continue
		}
		fieldName := strings.Trim(parts[0], "`")
		fieldType := strings.TrimSpace(parts[1])

		// Map OpenObserve types to ClickHouse-like types
		dataType := strings.ToLower(fieldType)
		if dataType == "" {
			dataType = "string"
		}

		hits = append(hits, map[string]any{
			"tag_key":       fieldName,
			"tag_type":      "tag",
			"tag_data_type": dataType,
			"priority":      uint8(4),
		})
	}

	c.logger.DebugContext(ctx, "openobserve: field keys metadata response",
		"stream", streamName, "type", streamType, "field_count", len(hits))

	return &ooResponse{
		Hits:        hits,
		Total:       len(hits),
		columnOrder: []string{"tag_key", "tag_type", "tag_data_type", "priority"},
	}, nil
}
