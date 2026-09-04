package openobservetelemetrystore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Query intent classification
// ---------------------------------------------------------------------------

// queryIntent represents the detected intent of a SQL query.
type queryIntent string

const (
	intentUnknown              queryIntent = "unknown"
	intentGetServicesList      queryIntent = "getServicesList"
	intentGetTopLevelOps       queryIntent = "getTopLevelOps"
	intentGetServices          queryIntent = "getServices"
	intentGetServicesError     queryIntent = "getServicesError"
	intentSearchTraces         queryIntent = "searchTraces"
	intentTraceSummary         queryIntent = "traceSummary"
	intentTracesCount          queryIntent = "tracesCount"
	intentTracesList           queryIntent = "tracesList"
	intentLogsQuery            queryIntent = "logsQuery"
	intentDistinctFilterValues queryIntent = "distinctFilterValues"
	intentSpanAttributeKeys    queryIntent = "spanAttributeKeys"
	intentLogAttributeKeys     queryIntent = "logAttributeKeys"
	intentTraceDetail          queryIntent = "traceDetail" // flamegraph, trace spans, etc. — must go through translateTraceDetailSQL
)

// classifyQuery detects the intent of a SQL query after argument interpolation.
func classifyQuery(sql string) queryIntent {
	lower := strings.ToLower(sql)

	// Remove SQL comments
	lower = regexp.MustCompile(`--.*$`).ReplaceAllString(lower, "")
	lower = strings.TrimSpace(lower)

	// SHOW CREATE TABLE
	if strings.HasPrefix(lower, "show create table") {
		return intentUnknown // handled separately
	}

	// ---- v5 builder queries (have __SELECT_KEY_ or __GROUP_BY_KEY_ aliases) ----
	// These should go through the generic translator (handleGenericQuery) which
	// preserves the original SQL structure and translates field/table names.
	// Without this early return, they'd be misclassified as intentSearchTraces
	// (because they contain resources_string) and routed to buildSearchTracesQuery
	// which discards the original SQL's filters, ordering, and aliases.
	if (strings.Contains(lower, "__select_key_") || strings.Contains(lower, "__group_by_key_")) &&
		(strings.Contains(lower, "signoz_index_v3") || strings.Contains(lower, "signoz_index_v2") || strings.Contains(lower, "signoz_spans")) {
		return intentTracesList
	}
	if (strings.Contains(lower, "__select_key_") || strings.Contains(lower, "__group_by_key_")) &&
		(strings.Contains(lower, "logs_v2") || strings.Contains(lower, "signoz_logs")) {
		return intentLogsQuery
	}

	// Tag attributes / metadata queries
	if isTagAttributesQuery(sql) {
		return intentUnknown
	}

	// Trace detail queries (flamegraph, trace spans, etc.) use ClickHouse-specific
	// syntax (any() aggregations, DISTINCT ON, ts_bucket_start) that must go through
	// translateTraceDetailSQL. Return intentTraceDetail so handleNativeQuery does NOT
	// intercept them — they fall through to the generic translator path.
	if strings.Contains(lower, "any(parent_span_id)") && strings.Contains(lower, "signoz_index_v3") {
		return intentTraceDetail
	}
	if strings.Contains(lower, "distinct on (span_id)") && strings.Contains(lower, "signoz_index_v3") {
		return intentTraceDetail
	}

	// Trace summary query
	if strings.Contains(lower, "trace_summary") ||
		(strings.Contains(lower, "min(start)") && strings.Contains(lower, "max(end)") && strings.Contains(lower, "sum(num_spans)")) {
		return intentTraceSummary
	}

	// Span attribute keys
	if strings.Contains(lower, "span_attributes_keys") || strings.Contains(lower, "span_attributes_keys") {
		return intentSpanAttributeKeys
	}

	// Log attribute keys
	if strings.Contains(lower, "log_attribute_keys") || strings.Contains(lower, "log_resource_keys") {
		return intentLogAttributeKeys
	}

	// Detect table reference to determine signal type
	isTracesQuery := strings.Contains(lower, "signoz_index_v3") ||
		strings.Contains(lower, "signoz_index_v2") ||
		strings.Contains(lower, "signoz_spans") ||
		strings.Contains(lower, "top_level_operations")
	isLogsQuery := strings.Contains(lower, "logs_v2") ||
		(strings.Contains(lower, "signoz_logs") && !strings.Contains(lower, "log_attribute"))

	// GetServicesList: SELECT DISTINCT ... service$$name FROM traces
	if strings.Contains(lower, "distinct") &&
		(strings.Contains(lower, "service$$name") || strings.Contains(lower, "service_name")) &&
		isTracesQuery &&
		!strings.Contains(lower, "quantile") &&
		!strings.Contains(lower, "count(") {
		return intentGetServicesList
	}

	// QBv5 services query: uses __result_N aliases and __group_by_key_ for service grouping
	// Must be checked BEFORE the top_level_operations check because QBV5 SQL may reference
	// top_level_operations in a CTE/subquery while the main intent is getServices.
	if strings.Contains(lower, "__result_") &&
		strings.Contains(lower, "__group_by_key_") &&
		strings.Contains(lower, "service") &&
		isTracesQuery {
		return intentGetServices
	}

	// GetTopLevelOperations: FROM top_level_operations
	if strings.Contains(lower, "top_level_operations") {
		return intentGetTopLevelOps
	}

	// GetServices error query: count(*) ... statusCode=2
	if strings.Contains(lower, "count(*)") &&
		strings.Contains(lower, "numerrors") &&
		isTracesQuery {
		return intentGetServicesError
	}

	// GetServices main query: quantile(0.99)(duration_nano) ... p99, avgDuration, numCalls
	if (strings.Contains(lower, "quantile") || strings.Contains(lower, "percentile")) &&
		strings.Contains(lower, "avgduration") &&
		strings.Contains(lower, "numcalls") {
		return intentGetServices
	}

	// SearchTraces: SELECT ... FROM traces WHERE trace_id=...
	if strings.Contains(lower, "trace_id") &&
		strings.Contains(lower, "span_id") &&
		strings.Contains(lower, "duration_nano") &&
		strings.Contains(lower, "resources_string") &&
		isTracesQuery {
		return intentSearchTraces
	}

	// Traces COUNT query
	if strings.Contains(lower, "count(*)") && isTracesQuery &&
		!strings.Contains(lower, "numcalls") &&
		!strings.Contains(lower, "numerrors") {
		return intentTracesCount
	}

	// Traces list query (via v3/v5 query builder)
	if isTracesQuery && !strings.Contains(lower, "quantile") {
		return intentTracesList
	}

	// Logs query
	if isLogsQuery {
		return intentLogsQuery
	}

	// Distinct filter values
	if strings.Contains(lower, "distinct") && (strings.Contains(lower, "operation_name") || strings.Contains(lower, "service_name")) {
		return intentDistinctFilterValues
	}

	return intentUnknown
}

// ---------------------------------------------------------------------------
// Native OpenObserve query builders
// ---------------------------------------------------------------------------

// buildNativeQuery constructs an OpenObserve-native SQL query for the given intent.
// The originalSQL (after arg interpolation) is used to extract parameters like
// service names, time ranges, trace IDs, etc.
func buildNativeQuery(intent queryIntent, originalSQL string) (stream string, streamType string, sql string) {
	switch intent {
	case intentGetServicesList:
		return buildGetServicesListQuery(originalSQL)
	case intentGetTopLevelOps:
		return buildGetTopLevelOpsQuery(originalSQL)
	case intentGetServices:
		return buildGetServicesQuery(originalSQL)
	case intentGetServicesError:
		return buildGetServicesErrorQuery(originalSQL)
	case intentSearchTraces:
		return buildSearchTracesQuery(originalSQL)
	case intentTraceSummary:
		return buildTraceSummaryQuery(originalSQL)
	case intentTracesCount:
		return buildTracesCountQuery(originalSQL)
	case intentTracesList:
		return buildTracesListQuery(originalSQL)
	case intentLogsQuery:
		return buildLogsQuery(originalSQL)
	case intentSpanAttributeKeys:
		return buildSpanAttributeKeysQuery(originalSQL)
	case intentLogAttributeKeys:
		return buildLogAttributeKeysQuery(originalSQL)
	case intentDistinctFilterValues:
		return buildDistinctFilterValuesQuery(originalSQL)
	default:
		return "", "", ""
	}
}

// extractTimeRange extracts start/end time values from the SQL.
// Returns values in microseconds for OpenObserve API.
func extractTimeRange(sql string) (startMicro, endMicro int64) {
	// Default: last 30 days
	now := currentTimeUnixMicro()
	startMicro = now - 30*24*3600*1e6
	endMicro = now + 24*3600*1e6

	// Match patterns like: timestamp >= 1234567890 (nanoseconds)
	// or _timestamp >= 1234567890 (microseconds)
	// or start_time >= 1234567890 (nanoseconds)
	re := regexp.MustCompile(`(?i)(?:_timestamp|timestamp|start_time)\s*>=\s*['"]?(\d{10,19})['"]?`)
	if m := re.FindStringSubmatch(sql); len(m) > 1 {
		v := parseInt64(m[1])
		if v > 1e18 {
			startMicro = v / 1000 // nanoseconds (19 digits) → microseconds
		} else if v > 1e12 {
			startMicro = v // already microseconds (13-18 digits)
		} else {
			startMicro = v * 1e6 // seconds → microseconds
		}
	}

	re = regexp.MustCompile(`(?i)(?:_timestamp|timestamp|start_time)\s*<=?\s*['"]?(\d{10,19})['"]?`)
	if m := re.FindStringSubmatch(sql); len(m) > 1 {
		v := parseInt64(m[1])
		if v > 1e18 {
			endMicro = v / 1000
		} else if v > 1e12 {
			endMicro = v
		} else {
			endMicro = v * 1e6
		}
	}

	return startMicro, endMicro
}

// extractServiceName extracts service_name value from SQL like: service_name = 'xxx'
func extractServiceName(sql string) string {
	re := regexp.MustCompile(`(?i)(?:service\$\$name|service_name)\s*=\s*'([^']+)'`)
	if m := re.FindStringSubmatch(sql); len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractTraceID extracts trace_id value from SQL like: trace_id=$1 or trace_id='xxx'
func extractTraceID(sql string) string {
	re := regexp.MustCompile(`(?i)trace_id\s*=\s*(?:\$1|'([^']+)')`)
	if m := re.FindStringSubmatch(sql); len(m) > 1 {
		return m[1]
	}
	// Also try to extract from interpolated values
	re2 := regexp.MustCompile(`(?i)trace_id\s*=\s*'([^']+)'`)
	if m := re2.FindStringSubmatch(sql); len(m) > 1 {
		return m[1]
	}
	return ""
}

// extractInValues extracts values from IN clause like: name In ('a','b','c')
func extractInValues(sql string, column string) []string {
	re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(column) + `\s+In\s*\(([^)]+)\)`)
	if m := re.FindStringSubmatch(sql); len(m) > 1 {
		vals := strings.Split(m[1], ",")
		var result []string
		for _, v := range vals {
			v = strings.TrimSpace(v)
			v = strings.Trim(v, "'\"")
			if v != "" {
				result = append(result, v)
			}
		}
		return result
	}
	return nil
}

// ---------------------------------------------------------------------------
// Individual query builders
// ---------------------------------------------------------------------------

func buildGetServicesListQuery(originalSQL string) (string, string, string) {
	startMicro, endMicro := extractTimeRange(originalSQL)
	sql := fmt.Sprintf(
		`SELECT DISTINCT service_name FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d`,
		startMicro, endMicro,
	)
	return "default", "traces", sql
}

func buildGetTopLevelOpsQuery(originalSQL string) (string, string, string) {
	startMicro, endMicro := extractTimeRange(originalSQL)
	// OpenObserve doesn't have a top_level_operations table.
	// Query the traces directly to get distinct operation/service combinations.
	sql := fmt.Sprintf(
		`SELECT operation_name as "name", service_name as "serviceName", MAX(_timestamp) as ts FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d GROUP BY operation_name, service_name ORDER BY ts DESC LIMIT 5000`,
		startMicro, endMicro,
	)
	return "default", "traces", sql
}

func buildGetServicesQuery(originalSQL string) (string, string, string) {
	startMicro, endMicro := extractTimeRange(originalSQL)
	lower := strings.ToLower(originalSQL)

	// Detect QBv5 query pattern: uses __result_N and __group_by_key_ aliases
	isQBV5 := strings.Contains(lower, "__result_") && strings.Contains(lower, "__group_by_key_")

	if isQBV5 {
		// QBv5 services query: return columns with __result_N aliases expected by readAsScalar
		// and __group_by_key_0_service_name expected by stripKeyAlias → service.name
		// OpenObserve duration is in microseconds; SigNoz expects nanoseconds → multiply by 1000
		//
		// IMPORTANT: The __result_N order MUST match the hardcoded index mapping in
		// mapQueryRangeRespToServices (implservices/module.go):
		//   aggIndexMappings[0] → column at __result_0 → NumCalls
		//   aggIndexMappings[1] → column at __result_1 → NumErrors
		//   aggIndexMappings[2] → column at __result_2 → Num4XX
		//   aggIndexMappings[3] → column at __result_3 → Percentile99
		//   aggIndexMappings[4] → column at __result_4 → AvgDuration
		sql := fmt.Sprintf(
			`SELECT service_name as "__group_by_key_0_service_name", `+
				`COUNT(*) as "__result_0", `+
				`SUM(CASE WHEN status_code = 2 THEN 1 ELSE 0 END) as "__result_1", `+
				`SUM(CASE WHEN http_status_code >= 400 AND http_status_code < 500 THEN 1 ELSE 0 END) as "__result_2", `+
				`PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration * 1000) as "__result_3", `+
				`AVG(duration * 1000) as "__result_4" `+
				`FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d `+
				`GROUP BY service_name`,
			startMicro, endMicro,
		)
		return "default", "traces", sql
	}

	// Old v3 query path
	svc := extractServiceName(originalSQL)

	// Extract operation names from IN clause
	ops := extractInValues(originalSQL, "name")
	opsFilter := ""
	if len(ops) > 0 {
		quoted := make([]string, len(ops))
		for i, op := range ops {
			quoted[i] = "'" + strings.ReplaceAll(op, "'", "''") + "'"
		}
		opsFilter = " AND operation_name IN (" + strings.Join(quoted, ",") + ")"
	}

	svcFilter := ""
	if svc != "" {
		svcFilter = fmt.Sprintf("service_name = '%s' AND ", svc)
	}

	// OpenObserve duration is in microseconds; SigNoz frontend expects nanoseconds.
	// Multiply by 1000 to convert.
	sql := fmt.Sprintf(
		`SELECT PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration * 1000) as p99, AVG(duration * 1000) as avgDuration, COUNT(*) as numCalls FROM "default" WHERE %s_timestamp >= %d AND _timestamp <= %d%s`,
		svcFilter, startMicro, endMicro, opsFilter,
	)
	return "default", "traces", sql
}

func buildGetServicesErrorQuery(originalSQL string) (string, string, string) {
	startMicro, endMicro := extractTimeRange(originalSQL)
	svc := extractServiceName(originalSQL)

	ops := extractInValues(originalSQL, "name")
	opsFilter := ""
	if len(ops) > 0 {
		quoted := make([]string, len(ops))
		for i, op := range ops {
			quoted[i] = "'" + strings.ReplaceAll(op, "'", "''") + "'"
		}
		opsFilter = " AND operation_name IN (" + strings.Join(quoted, ",") + ")"
	}

	svcFilter := ""
	if svc != "" {
		svcFilter = fmt.Sprintf("service_name = '%s' AND ", svc)
	}

	sql := fmt.Sprintf(
		`SELECT COUNT(*) as numErrors FROM "default" WHERE %s_timestamp >= %d AND _timestamp <= %d AND status_code = 2%s`,
		svcFilter, startMicro, endMicro, opsFilter,
	)
	return "default", "traces", sql
}

func buildSearchTracesQuery(originalSQL string) (string, string, string) {
	traceID := extractTraceID(originalSQL)
	startMicro, endMicro := extractTimeRange(originalSQL)

	filters := "_timestamp >= " + fmt.Sprintf("%d", startMicro) + " AND _timestamp <= " + fmt.Sprintf("%d", endMicro)
	if traceID != "" {
		filters = fmt.Sprintf("trace_id = '%s' AND ", traceID) + filters
	}

	// OpenObserve traces schema is flat. Map fields to what the caller expects.
	// duration is in microseconds in O2, caller expects duration_nano → multiply by 1000
	// resources_string doesn't exist → return empty JSON
	// attributes_string/number/bool don't exist as separate maps → return empty JSON
	sql := fmt.Sprintf(
		`SELECT
			_timestamp as "timestamp",
			duration * 1000 as duration_nano,
			span_id,
			trace_id,
			CASE WHEN status_code = 2 THEN true ELSE false END as has_error,
			span_kind as kind,
			service_name as "resource_string_service$$name",
			operation_name as name,
			links as references,
			'{}' as attributes_string,
			'{}' as attributes_number,
			'{}' as attributes_bool,
			'{}' as resources_string,
			events,
			status_message,
			CASE WHEN status_code = 1 THEN 'OK' WHEN status_code = 2 THEN 'ERROR' ELSE 'UNSET' END as status_code_string,
			span_kind as kind_string
		FROM "default" WHERE %s`,
		filters,
	)
	return "default", "traces", sql
}

func buildTraceSummaryQuery(originalSQL string) (string, string, string) {
	traceID := extractTraceID(originalSQL)
	startMicro, endMicro := extractTimeRange(originalSQL)

	filters := "_timestamp >= " + fmt.Sprintf("%d", startMicro) + " AND _timestamp <= " + fmt.Sprintf("%d", endMicro)
	if traceID != "" {
		filters = fmt.Sprintf("trace_id = '%s' AND ", traceID) + filters
	}

	// OpenObserve doesn't have a trace_summary table.
	// Compute summary from the traces directly.
	// _timestamp is microseconds, duration is microseconds.
	// end = max(start_time + duration) in microseconds → _timestamp + duration/1000 keeps microseconds.
	sql := fmt.Sprintf(
		`SELECT
			trace_id,
			MIN(_timestamp) as start,
			MAX(_timestamp + duration / 1000) as "end",
			COUNT(*) as num_spans
		FROM "default" WHERE %s
		GROUP BY trace_id`,
		filters,
	)
	return "default", "traces", sql
}

func buildTracesCountQuery(originalSQL string) (string, string, string) {
	startMicro, endMicro := extractTimeRange(originalSQL)

	sql := fmt.Sprintf(
		`SELECT COUNT(*) as "__result_0" FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d`,
		startMicro, endMicro,
	)
	return "default", "traces", sql
}

func buildTracesListQuery(originalSQL string) (string, string, string) {
	// If the SQL contains v5 builder aliases (__SELECT_KEY_), it should be
	// handled by the generic translator which preserves the original SQL
	// structure and translates field/table names.
	if strings.Contains(strings.ToLower(originalSQL), "__select_key_") ||
		strings.Contains(strings.ToLower(originalSQL), "__group_by_key_") {
		return "", "", "" // fall through to handleGenericQuery
	}

	// For traces list queries from the v3/v5 query builder, the SQL is complex.
	// Apply basic translations and let the query run against O2.
	startMicro, endMicro := extractTimeRange(originalSQL)
	lower := strings.ToLower(originalSQL)

	// Detect if it's a simple list query (no aggregation)
	if !strings.Contains(lower, "count(") && !strings.Contains(lower, "quantile") && !strings.Contains(lower, "percentile") {
		// Raw traces list: return raw span data with field names matching what the
		// SigNoz frontend expects (service.name, http_method, response_status_code, etc.)
		sql := fmt.Sprintf(
			`SELECT _timestamp as "timestamp", duration * 1000 as duration_nano, span_id, trace_id, `+
				`service_name as "service.name", operation_name as name, `+
				`CASE WHEN status_code = 2 THEN 1 ELSE 0 END as has_error, `+
				`span_kind as kind, span_kind as kind_string, `+
				`http_method, http_status_code as response_status_code `+
				`FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d `+
				`ORDER BY _timestamp DESC LIMIT 50`,
			startMicro, endMicro,
		)
		return "default", "traces", sql
	}
	// Complex aggregation — let it fall through
	return "", "", ""
}

func buildLogsQuery(originalSQL string) (string, string, string) {
	startMicro, endMicro := extractTimeRange(originalSQL)
	lower := strings.ToLower(originalSQL)

	// Handle time series queries (frequency chart): detect toStartOfInterval or time-based GROUP BY
	// with aggregation (COUNT, SUM, etc.) and group-by fields
	if strings.Contains(lower, "tostartofinterval") || strings.Contains(lower, "toStartOfInterval") {
		return buildLogsTimeSeriesQuery(originalSQL, lower, startMicro, endMicro)
	}

	// Handle DISTINCT queries: SELECT DISTINCT field FROM logs ...
	if strings.Contains(lower, "distinct") {
		distinctRe := regexp.MustCompile(`(?i)SELECT\s+DISTINCT\s+(\w+)`)
		if m := distinctRe.FindStringSubmatch(lower); len(m) > 1 {
			field := m[1]
			o2Field := mapLogField(field)
			sql := fmt.Sprintf(
				`SELECT DISTINCT %s FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d LIMIT 1000`,
				o2Field, startMicro, endMicro,
			)
			return "default", "logs", sql
		}
	}

	// Handle COUNT queries (without time series)
	if strings.Contains(lower, "count(") && !strings.Contains(lower, "group") {
		sql := fmt.Sprintf(
			`SELECT COUNT(*) as "count" FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d`,
			startMicro, endMicro,
		)
		return "default", "logs", sql
	}

	// Handle simple list queries: return raw log data
	sql := fmt.Sprintf(
		`SELECT * FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d `+
			`ORDER BY _timestamp DESC LIMIT 100`,
		startMicro, endMicro,
	)
	return "default", "logs", sql
}

// buildLogsTimeSeriesQuery builds a native OpenObserve time series query for logs.
// The QBv5 SQL format looks like:
//
//	SELECT toStartOfInterval(fromUnixTimestamp64Nano(timestamp), INTERVAL 5 SECOND) AS ts,
//	       toString(multiIf(severity_text <> '', severity_text, NULL)) AS `__GROUP_BY_KEY_0_severity_text`,
//	       count() AS __result_0
//	FROM signoz_logs.distributed_logs_v2
//	WHERE timestamp >= '...' AND ts_bucket_start >= ... AND timestamp < '...' AND ts_bucket_start <= ...
//	GROUP BY ts, `__GROUP_BY_KEY_0_severity_text`
func buildLogsTimeSeriesQuery(originalSQL, lower string, startMicro, endMicro int64) (string, string, string) {
	// Extract step interval from toStartOfInterval(..., INTERVAL N SECOND/MINUTE)
	stepSeconds := int64(5) // default 5 seconds
	intervalRe := regexp.MustCompile(`(?i)INTERVAL\s+(\d+)\s+(SECOND|MINUTE|HOUR|DAY)`)
	if m := intervalRe.FindStringSubmatch(originalSQL); len(m) >= 3 {
		n := parseInt64(m[1])
		switch strings.ToUpper(m[2]) {
		case "SECOND":
			stepSeconds = n
		case "MINUTE":
			stepSeconds = n * 60
		case "HOUR":
			stepSeconds = n * 3600
		case "DAY":
			stepSeconds = n * 86400
		}
	}
	stepMicro := stepSeconds * 1_000_000

	// Time bucket expression for OpenObserve
	timeBucketExpr := fmt.Sprintf("FLOOR(_timestamp / %d) * %d", stepMicro, stepMicro)

	// Extract non-time group-by fields from backtick-quoted aliases:
	// Pattern: <expression> AS `__GROUP_BY_KEY_0_<field>`
	aliasRe := regexp.MustCompile("(?i)AS\\s+`(__group_by_key_\\d+_(\\w+))`")
	aliasMatches := aliasRe.FindAllStringSubmatch(originalSQL, -1)

	// Also try unquoted aliases: AS __group_by_key_0_<field>
	if len(aliasMatches) == 0 {
		aliasRe = regexp.MustCompile(`(?i)AS\s+(__group_by_key_\d+_(\w+))`)
		aliasMatches = aliasRe.FindAllStringSubmatch(originalSQL, -1)
	}

	// Extract aggregation: count() AS __result_0, COUNT(*) AS __result_0, etc.
	aggRe := regexp.MustCompile(`(?i)(count\s*\(\s*\*?\s*\)|sum\s*\([^)]*\)|avg\s*\([^)]*\)|min\s*\([^)]*\)|max\s*\([^)]*\))\s+AS\s+` + "`?" + `(__result_\d+)` + "`?")
	aggMatches := aggRe.FindAllStringSubmatch(originalSQL, -1)

	// Build SELECT clause - use original aliases so the QBv5 pipeline can map the response
	var selectParts []string
	// Time bucket: use the same alias as the original SQL (usually 'ts')
	timeBucketAlias := extractTimeBucketAlias(originalSQL)
	if timeBucketAlias == "" {
		timeBucketAlias = "__GROUP_BY_KEY_0"
	}
	selectParts = append(selectParts,
		fmt.Sprintf("%s AS %s", timeBucketExpr, timeBucketAlias))

	// Add non-time group-by fields - use original aliases
	var nonTimeGroupBy []string
	for _, m := range aliasMatches {
		alias := m[1] // e.g. __GROUP_BY_KEY_0_severity_text (original alias with backticks removed)
		field := m[2] // e.g. severity_text
		field = mapLogFieldForQuery(field)
		selectParts = append(selectParts, fmt.Sprintf("%s AS %s", field, alias))
		nonTimeGroupBy = append(nonTimeGroupBy, field)
	}

	// Add aggregation selects - use original aliases (__result_N)
	for _, m := range aggMatches {
		agg := m[1]
		alias := m[2]
		// Normalize count() to COUNT(*)
		if regexp.MustCompile(`(?i)^count\s*\(\s*\)$`).MatchString(agg) {
			agg = "COUNT(*)"
		}
		selectParts = append(selectParts, fmt.Sprintf("%s AS %s", agg, alias))
	}

	// Extract WHERE filters from original SQL (excluding timestamp conditions)
	filterClause := extractLogsFilterClause(originalSQL)

	// Build WHERE clause
	whereClause := fmt.Sprintf("_timestamp >= %d AND _timestamp <= %d", startMicro, endMicro)
	if filterClause != "" {
		whereClause += " AND " + filterClause
	}

	// Build GROUP BY clause using actual expressions (not aliases)
	var groupByParts []string
	groupByParts = append(groupByParts, timeBucketExpr)
	groupByParts = append(groupByParts, nonTimeGroupBy...)

	// ORDER BY using the original time bucket alias
	sql := fmt.Sprintf(
		`SELECT %s FROM "default" WHERE %s GROUP BY %s ORDER BY %s ASC`,
		strings.Join(selectParts, ", "),
		whereClause,
		strings.Join(groupByParts, ", "),
		timeBucketAlias,
	)

	return "default", "logs", sql
}

// extractTimeBucketAlias extracts the alias of the toStartOfInterval expression.
// E.g. "toStartOfInterval(fromUnixTimestamp64Nano(timestamp), INTERVAL 5 SECOND) AS ts" → "ts"
func extractTimeBucketAlias(sql string) string {
	// Match toStartOfInterval(...) AS <alias>, handling one level of nested parentheses
	// Pattern: toStartOfInterval( <stuff> ( <stuff> ) <stuff> ) AS alias
	re := regexp.MustCompile(`(?i)toStartOfInterval\s*\((?:[^()]*|\((?:[^()]*|\([^()]*\))*\))*\)\s+AS\s+` + "`?" + `(\w+)` + "`?")
	if m := re.FindStringSubmatch(sql); len(m) > 1 {
		return m[1]
	}
	return ""
}

// mapLogFieldForQuery maps ClickHouse log field names to OpenObserve equivalents for SQL queries.
func mapLogFieldForQuery(field string) string {
	lower := strings.ToLower(field)
	switch lower {
	case "timestamp":
		return "_timestamp"
	case "severity_text":
		return "severity"
	case "severity_number":
		return "severity"
	default:
		return field
	}
}

// extractLogsFilterClause extracts non-timestamp WHERE conditions from the original SQL.
// It looks for filter expressions after WHERE and before GROUP BY.
func extractLogsFilterClause(originalSQL string) string {
	// Find WHERE clause content
	whereRe := regexp.MustCompile(`(?i)WHERE\s+(.+?)(?:\s+GROUP\s+BY|\s+ORDER\s+BY|\s+LIMIT|\s*$)`)
	m := whereRe.FindStringSubmatch(originalSQL)
	if len(m) < 2 {
		return ""
	}
	whereContent := m[1]

	// Remove timestamp and ts_bucket_start conditions
	// Match patterns like:
	//   timestamp >= 123, timestamp >= '123', _timestamp <= 456
	//   ts_bucket_start >= 789, ts_bucket_start <= 101112
	tsRe := regexp.MustCompile(`(?i)(?:AND|OR)?\s*(?:_?timestamp|ts_bucket_start)\s*(?:>=|<=|>|<|=|!=)\s*(?:'[^']*'|\d+)\s*`)
	cleaned := tsRe.ReplaceAllString(whereContent, "")
	// Clean up leading/trailing AND/OR
	cleaned = regexp.MustCompile(`(?i)^\s*(AND|OR)\s+`).ReplaceAllString(cleaned, "")
	cleaned = regexp.MustCompile(`(?i)\s+(AND|OR)\s*$`).ReplaceAllString(cleaned, "")
	// Clean up double AND/OR
	cleaned = regexp.MustCompile(`(?i)(AND|OR)\s+(AND|OR)`).ReplaceAllString(cleaned, "${1}")
	cleaned = strings.TrimSpace(cleaned)

	if cleaned == "" {
		return ""
	}
	return cleaned
}

// mapLogField maps ClickHouse log field names to OpenObserve field names.
func mapLogField(chField string) string {
	switch strings.ToLower(chField) {
	case "severity_text":
		return "severity"
	case "severity_number":
		return "severity"
	default:
		return chField
	}
}

func buildSpanAttributeKeysQuery(originalSQL string) (string, string, string) {
	// Return distinct attribute keys from traces
	sql := `SELECT DISTINCT 'service_name' as "name" FROM "default" LIMIT 1`
	return "default", "traces", sql
}

func buildLogAttributeKeysQuery(originalSQL string) (string, string, string) {
	// Return empty result for attribute keys queries
	return "default", "logs", `SELECT 'body' as "name" FROM "default" LIMIT 0`
}

func buildDistinctFilterValuesQuery(originalSQL string) (string, string, string) {
	// DISTINCT filter values: SELECT DISTINCT operation_name/service_name FROM traces
	startMicro, endMicro := extractTimeRange(originalSQL)
	lower := strings.ToLower(originalSQL)

	// Determine signal type
	isTraces := strings.Contains(lower, "signoz_index_v3") || strings.Contains(lower, "signoz_spans")
	if isTraces {
		// Detect which field is being queried
		if strings.Contains(lower, "operation_name") || strings.Contains(lower, "name") {
			sql := fmt.Sprintf(
				`SELECT DISTINCT operation_name FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d LIMIT 1000`,
				startMicro, endMicro,
			)
			return "default", "traces", sql
		}
		if strings.Contains(lower, "service_name") {
			sql := fmt.Sprintf(
				`SELECT DISTINCT service_name FROM "default" WHERE _timestamp >= %d AND _timestamp <= %d LIMIT 1000`,
				startMicro, endMicro,
			)
			return "default", "traces", sql
		}
	}
	return "", "", ""
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func currentTimeUnixMicro() int64 {
	return time.Now().UnixMicro()
}

func parseInt64(s string) int64 {
	var v int64
	fmt.Sscanf(s, "%d", &v)
	return v
}

// handleNativeQuery tries to classify the query and execute a native OpenObserve query.
// Returns (response, handled, error).
// If handled is false, the caller should fall through to the generic translator.
func (c *ooConn) handleNativeQuery(ctx context.Context, sql string) (*ooResponse, bool, error) {
	intent := classifyQuery(sql)

	// Intents that we handle with native queries
	switch intent {
	case intentGetServicesList, intentGetTopLevelOps, intentGetServices,
		intentGetServicesError, intentSearchTraces, intentTraceSummary,
		intentSpanAttributeKeys, intentLogAttributeKeys,
		intentLogsQuery, intentTracesCount, intentTracesList,
		intentDistinctFilterValues:

		if intent == intentLogsQuery {
			c.logger.InfoContext(ctx, "openobserve: intentLogsQuery original SQL", "sql_full", sql[:min(len(sql), 1500)])
		}

		stream, streamType, nativeSQL := buildNativeQuery(intent, sql)
		if nativeSQL == "" {
			return nil, false, nil // fall through to generic
		}

		if intent == intentLogsQuery {
			c.logger.InfoContext(ctx, "openobserve: intentLogsQuery native SQL", "native_sql", nativeSQL[:min(len(nativeSQL), 1500)])
		}

		c.logger.InfoContext(ctx, "openobserve: native query",
			"intent", string(intent), "stream", stream, "type", streamType, "native_sql", nativeSQL)

		resp, err := c.executeOpenObserveQuery(ctx, stream, streamType, nativeSQL)
		if err != nil {
			return nil, true, err
		}
		// Use the native SQL (not the original ClickHouse SQL) to extract column order,
		// since the response keys correspond to the native SQL aliases.
		resp.columnOrder = extractColumnOrderFromSQL(nativeSQL)

		// Detect if this is a time series / aggregation query (has __GROUP_BY_KEY_ or __SELECT_KEY_ aliases)
		isTimeSeries := strings.Contains(strings.ToLower(nativeSQL), "__group_by_key_") ||
			strings.Contains(strings.ToLower(nativeSQL), "__select_key_")

		if !isTimeSeries {
			// Only do log row transformation for non-time-series logs queries.
			// Time series queries have their own column structure that must be preserved.

			// OpenObserve stores _timestamp in microseconds, but SigNoz expects
			// nanoseconds for logs/traces queries. Convert the "timestamp" field
			// from microseconds to nanoseconds.
			if intent == intentLogsQuery || intent == intentTracesList || intent == intentTracesCount {
				c.logger.DebugContext(ctx, "converting timestamps micro to nano", "hits_count", len(resp.Hits))
				convertTimestampsMicroToNano(resp.Hits)
				if len(resp.Hits) > 0 {
					c.logger.DebugContext(ctx, "after timestamp conversion", "first_timestamp", resp.Hits[0]["timestamp"])
				}
			}

			// Restructure flat OpenObserve log rows into the nested format
			// (attributes_string, resources_string, etc.) that SigNoz frontend expects.
			if intent == intentLogsQuery {
				transformLogRowsForSigNoz(resp.Hits)
				// Update columnOrder to reflect the restructured fields
				resp.columnOrder = []string{
					"timestamp", "body", "severity_text", "severity_number",
					"service_name", "trace_id", "span_id", "trace_flags",
					"id", "scope_name", "scope_version", "scope_string",
					"attributes_string", "attributes_number", "attributes_bool",
					"resources_string",
				}
			}
		} else {
			// For time series queries, the QBv5 pipeline handles timestamp conversion.
			// OpenObserve returns _timestamp in microseconds. The pipeline expects
			// nanosecond timestamps (ClickHouse convention) and converts to ms internally.
			// So we multiply microsecond time buckets by 1000 to look like nanoseconds.
			timeBucketAlias := extractTimeBucketAlias(nativeSQL)
			if timeBucketAlias == "" {
				timeBucketAlias = "ts"
			}
			for _, hit := range resp.Hits {
				if ts, ok := hit[timeBucketAlias]; ok {
					if tsFloat, err := toFloat64(ts); err == nil {
						// Multiply by 1000 so the pipeline treats microseconds as nanoseconds
						// and converts to milliseconds correctly (micro * 1000 / 1e6 = micro / 1000 = ms)
						hit[timeBucketAlias] = int64(tsFloat * 1000)
					}
				}
			}
			c.logger.InfoContext(ctx, "openobserve: time series response", "columns", resp.columnOrder, "rows", len(resp.Hits))
		}

		return resp, true, nil

	default:
		return nil, false, nil // fall through to generic translator
	}
}

// executeOpenObserveQuery executes a pre-built OpenObserve SQL query against the given stream.
func (c *ooConn) executeOpenObserveQuery(ctx context.Context, stream, streamType, sql string) (*ooResponse, error) {
	if stream == "" {
		stream = "default"
	}
	if streamType == "" {
		streamType = "traces"
	}

	// Extract time range from SQL
	startMicro, endMicro := extractTimeRange(sql)

	reqBody := searchRequest{
		Query: searchQuery{
			SQL:       sql,
			StartTime: startMicro,
			EndTime:   endMicro,
			From:      0,
			Size:      10000,
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal search request: %w", err)
	}

	url := fmt.Sprintf("%s/api/%s/_search?type=%s", c.endpoint, c.orgID, streamType)
	c.logger.InfoContext(ctx, "openobserve: executeOpenObserveQuery",
		"url", url, "stream", stream, "type", streamType, "sql", sql,
		"start_time", startMicro, "end_time", endMicro)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		c.logger.WarnContext(ctx, "openobserve query failed",
			"status", resp.StatusCode, "body", string(respBody), "sql", sql)
		return &ooResponse{Hits: []map[string]any{}, Total: 0}, nil
	}

	var ooResp ooResponse
	if err := json.Unmarshal(respBody, &ooResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	c.logger.InfoContext(ctx, "openobserve: query response",
		"hits_count", len(ooResp.Hits), "total", ooResp.Total, "body_preview", string(respBody)[:min(len(respBody), 500)])

	return &ooResp, nil
}

// convertTimestampsMicroToNano converts the "timestamp" or "_timestamp" field in each hit
// from microseconds (OpenObserve _timestamp) to a time.Time-compatible string
// (RFC3339Nano) that SigNoz response handlers can parse correctly.
func convertTimestampsMicroToNano(hits []map[string]any) {
	for _, hit := range hits {
		// OpenObserve uses _timestamp; after rename it becomes timestamp
		for _, key := range []string{"timestamp", "_timestamp", "ts"} {
			if v, ok := hit[key]; ok {
				var micro int64
				switch val := v.(type) {
				case float64:
					micro = int64(val)
				case int64:
					micro = val
				case json.Number:
					if n, err := val.Int64(); err == nil {
						micro = n
					}
				}
				if micro > 0 {
					t := time.Unix(0, micro*1000) // micro * 1000 = nanoseconds
					hit[key] = t.UTC().Format(time.RFC3339Nano)
				}
			}
		}
	}
}

// o2ResourceFields is the set of OpenObserve log fields that map to
// OpenTelemetry resource attributes. These are stored flat in O2 but
// the SigNoz frontend expects them nested under "resources_string".
var o2ResourceFields = map[string]string{
	"container_runtime":           "container.runtime",
	"deployment_environment":      "deployment.environment",
	"host_name":                   "host.name",
	"os_type":                     "os.type",
	"process_command_args":        "process.command_args",
	"process_executable_name":     "process.executable.name",
	"process_executable_path":     "process.executable.path",
	"process_owner":               "process.owner",
	"process_pid":                 "process.pid",
	"process_runtime_description": "process.runtime.description",
	"process_runtime_name":        "process.runtime.name",
	"process_runtime_version":     "process.runtime.version",
	"service_name":                "service.name",
	"service_namespace":           "service.namespace",
	"service_version":             "service.version",
	"telemetry_sdk_language":      "telemetry.sdk.language",
}

// o2SystemFields are fields that are part of the log record itself
// and should not be classified as attributes or resources.
var o2SystemFields = map[string]bool{
	"_timestamp":                   true,
	"timestamp":                    true,
	"body":                         true,
	"severity":                     true,
	"severity_text":                true,
	"severity_number":              true,
	"span_id":                      true,
	"trace_id":                     true,
	"trace_flags":                  true,
	"id":                           true,
	"scope_name":                   true,
	"scope_version":                true,
	"instrumentation_library_name": true,
	"dropped_attributes_count":     true,
	"attributes_string":            true,
	"attributes_number":            true,
	"attributes_bool":              true,
	"resources_string":             true,
	"scope_string":                 true,
}

// transformLogRowsForSigNoz restructures flat OpenObserve log rows into
// the nested format that the SigNoz frontend expects for log detail views.
//
// OpenObserve stores all fields flat (e.g. host_name, service_name, order_id).
// SigNoz expects them grouped:
//   - resources_string: {"host.name": "...", "service.name": "..."}
//   - attributes_string: {"order_id": "...", "currency": "..."}
//   - attributes_number: {"amount": 70.77}
//   - attributes_bool: {}
//   - Plus system fields: body, severity_text, span_id, trace_id, etc.
func transformLogRowsForSigNoz(hits []map[string]any) {
	for i, hit := range hits {
		resourcesString := map[string]any{}
		attributesString := map[string]any{}
		attributesNumber := map[string]any{}
		attributesBool := map[string]any{}

		// Collect all keys first to avoid map modification during iteration
		keys := make([]string, 0, len(hit))
		for k := range hit {
			keys = append(keys, k)
		}

		for _, key := range keys {
			val := hit[key]

			// Check if it's a resource field
			if dottedName, isResource := o2ResourceFields[key]; isResource {
				resourcesString[dottedName] = val
				delete(hit, key)
				continue
			}

			// Check if it's a system field
			if o2SystemFields[key] {
				continue
			}

			// It's an attribute — classify by type
			switch val.(type) {
			case float64:
				// Check if it's actually an integer
				if f, ok := val.(float64); ok && f == float64(int64(f)) {
					attributesString[key] = val
				} else {
					attributesNumber[key] = val
				}
			case bool:
				attributesBool[key] = val
			default:
				attributesString[key] = val
			}
			delete(hit, key)
		}

		// Map O2 field names to SigNoz field names
		if sev, ok := hit["severity"]; ok {
			hit["severity_text"] = sev
			delete(hit, "severity")
		}

		// Rename _timestamp to timestamp (convertTimestampsMicroToNano already converted it)
		if ts, ok := hit["_timestamp"]; ok {
			hit["timestamp"] = ts
			delete(hit, "_timestamp")
		}

		// Set trace_flags if trace_id is present
		if traceID, ok := hit["trace_id"]; ok && traceID != "" && traceID != nil {
			hit["trace_flags"] = 1
		} else {
			hit["trace_flags"] = 0
		}

		// Set scope_name from instrumentation_library_name
		if iln, ok := hit["instrumentation_library_name"]; ok {
			hit["scope_name"] = iln
		}

		// Generate a unique ID for the log entry using the timestamp string
		if _, ok := hit["id"]; !ok {
			if ts, ok := hit["timestamp"]; ok {
				hit["id"] = fmt.Sprintf("o2-%v-%d", ts, i)
			} else {
				hit["id"] = fmt.Sprintf("o2-log-%d", i)
			}
		}

		// Clean up fields that shouldn't be in the output
		delete(hit, "instrumentation_library_name")
		delete(hit, "dropped_attributes_count")

		// Set the nested objects
		hit["attributes_string"] = attributesString
		hit["attributes_number"] = attributesNumber
		hit["attributes_bool"] = attributesBool
		hit["resources_string"] = resourcesString
		hit["scope_string"] = map[string]any{}
	}
}
