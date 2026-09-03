package openobservetelemetrystore

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Parenthesis-aware helpers
// ---------------------------------------------------------------------------

// splitTopLevelArgs splits a comma-separated argument list respecting nested
// parentheses and single-quoted string literals.
func splitTopLevelArgs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var args []string
	depth := 0
	inStr := false
	start := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' && !inStr {
			inStr = true
			continue
		}
		if ch == '\'' && inStr {
			// check escaped quote
			if i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inStr = false
			continue
		}
		if inStr {
			continue
		}
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
		} else if ch == ',' && depth == 0 {
			args = append(args, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	args = append(args, strings.TrimSpace(s[start:]))
	return args
}

// findClosingParen returns the index of the closing ')' for the opening '(' at
// pos.  Returns -1 when not found.
func findClosingParen(s string, pos int) int {
	depth := 0
	inStr := false
	for i := pos; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' {
			inStr = !inStr
			continue
		}
		if inStr {
			continue
		}
		if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// replaceFunc parses the query for calls to funcName( and calls replacer with
// the raw argument string.  The replacer returns the replacement text.
func replaceFunc(query, funcName string, replacer func(args string) string) string {
	result := query
	for {
		idx := strings.Index(result, funcName+"(")
		if idx == -1 {
			// also try case-insensitive
			lower := strings.ToLower(result)
			idx = strings.Index(lower, strings.ToLower(funcName)+"(")
			if idx == -1 {
				break
			}
		}
		parenStart := idx + len(funcName)
		closeIdx := findClosingParen(result, parenStart)
		if closeIdx == -1 {
			break
		}
		argsStr := result[parenStart+1 : closeIdx]
		replacement := replacer(argsStr)
		result = result[:idx] + replacement + result[closeIdx+1:]
	}
	return result
}

// ---------------------------------------------------------------------------
// ClickHouse field → OpenObserve flat field mappings (traces)
// ---------------------------------------------------------------------------

// resourceFieldMap maps resource.<dotted> to flat OpenObserve field names.
var resourceFieldMap = map[string]string{
	"service.name":           "service_name",
	"service.namespace":      "service_namespace",
	"service.version":        "service_version",
	"telemetry.sdk.name":     "telemetry_sdk_name",
	"telemetry.sdk.language": "telemetry_sdk_language",
	"telemetry.sdk.version":  "telemetry_sdk_version",
}

// scopeFieldMap maps scope.<dotted> to flat OpenObserve field names.
var scopeFieldMap = map[string]string{
	"name":    "scope_name",
	"version": "scope_version",
}

// translateResourceScopeField converts resource.`x.y` or scope.`x` patterns
// to the flat OpenObserve column name.
func translateResourceScopeField(q string) string {
	// resource.`key` or resource."key"
	reRes := regexp.MustCompile("(?i)resource\\.\\x60([^\\x60]+)\\x60")
	q = reRes.ReplaceAllStringFunc(q, func(match string) string {
		sub := reRes.FindStringSubmatch(match)
		key := sub[1]
		if flat, ok := resourceFieldMap[key]; ok {
			return flat
		}
		// fallback: replace dots with underscores
		return "resource_" + strings.ReplaceAll(key, ".", "_")
	})

	// scope.`key`
	reScope := regexp.MustCompile("(?i)scope\\.\\x60([^\\x60]+)\\x60")
	q = reScope.ReplaceAllStringFunc(q, func(match string) string {
		sub := reScope.FindStringSubmatch(match)
		key := sub[1]
		if flat, ok := scopeFieldMap[key]; ok {
			return flat
		}
		return "scope_" + strings.ReplaceAll(key, ".", "_")
	})

	// Also handle resource.key without backticks (e.g. resource.service.name)
	reResPlain := regexp.MustCompile(`(?i)resource\.([a-zA-Z_][a-zA-Z0-9_.]+)`)
	q = reResPlain.ReplaceAllStringFunc(q, func(match string) string {
		// skip if already inside a quoted string
		sub := reResPlain.FindStringSubmatch(match)
		key := sub[1]
		if flat, ok := resourceFieldMap[key]; ok {
			return flat
		}
		return "resource_" + strings.ReplaceAll(key, ".", "_")
	})

	return q
}

// ---------------------------------------------------------------------------
// Main translator
// ---------------------------------------------------------------------------

// translateClickHouseToOpenObserve converts ClickHouse SQL dialect to standard SQL
// compatible with OpenObserve. This is a best-effort translation; not all ClickHouse
// functions have direct equivalents.
func translateClickHouseToOpenObserve(query string) string {
	if query == "" {
		return query
	}

	// Skip non-SELECT queries (CREATE, INSERT, ALTER, DROP, EXPLAIN, SHOW)
	trimmed := strings.TrimSpace(query)
	upper := strings.ToUpper(trimmed)
	for _, prefix := range []string{"CREATE", "INSERT", "ALTER", "DROP", "EXPLAIN", "SHOW", "SET"} {
		if strings.HasPrefix(upper, prefix) {
			return query
		}
	}

	q := query

	// ---- Protect __SELECT_KEY_ / __GROUP_BY_KEY_ aliases ----
	// The v5 builder generates aliases like `__SELECT_KEY_0_service.name`.
	// We must preserve the dots in these aliases so that stripKeyAlias (in consume.go)
	// can recover the original field name (e.g. "service.name").
	// Replace them with placeholders before any field translations run.
	keyAliasProtectRe := regexp.MustCompile(`(?i)(__+(?:SELECT|GROUP_BY)_KEY_\d+_[\w.]+)`)
	keyAliasPlaceholders := []string{}
	q = keyAliasProtectRe.ReplaceAllStringFunc(q, func(match string) string {
		idx := len(keyAliasPlaceholders)
		keyAliasPlaceholders = append(keyAliasPlaceholders, match)
		return fmt.Sprintf("__KEYALIAS_PLACEHOLDER_%d__", idx)
	})

	// Remove FORMAT JSON clause
	q = regexp.MustCompile(`(?i)\bFORMAT\s+JSON\s*$`).ReplaceAllString(q, "")

	// Remove ClickHouse sign() index hints: sign(idx_name)
	q = regexp.MustCompile(`(?i)\bsign\(\w+\)`).ReplaceAllString(q, "")

	// Remove SETTINGS clause
	q = regexp.MustCompile(`(?i)\s+SETTINGS\s+.*$`).ReplaceAllString(q, "")

	// ---- Backtick-quoted identifiers ----
	// resource.`service.name` → service_name  (must run before generic backtick removal)
	q = translateResourceScopeField(q)

	// Generic: remove remaining backticks around identifiers
	q = strings.ReplaceAll(q, "`", "")

	// ---- Strip ts_bucket_start conditions (ClickHouse-specific, not in OpenObserve) ----
	q = regexp.MustCompile(`(?i)\s+AND\s+ts_bucket_start\s*(?:>=|<=|>|<|=|!=)\s*[^\s)]+`).ReplaceAllString(q, "")
	q = regexp.MustCompile(`(?i)ts_bucket_start\s*(?:>=|<=|>|<|=|!=)\s*[^\s)]+\s+AND\s+`).ReplaceAllString(q, "")
	q = regexp.MustCompile(`(?i)\bWHERE\s+AND\b`).ReplaceAllString(q, "WHERE")
	q = regexp.MustCompile(`(?i)\bAND\s+AND\b`).ReplaceAllString(q, "AND")

	// ---- GLOBAL IN → IN ----
	q = regexp.MustCompile(`(?i)\bGLOBAL\s+IN\b`).ReplaceAllString(q, "IN")

	// ---- ClickHouse attribute map columns → NULL ----
	// OpenObserve traces don't have attributes_number, attributes_string, attributes_bool
	// (those are ClickHouse Map columns). The expression builder generates patterns like:
	//   attributes_number::String LIKE '%status_code%'   (from mapContains)
	//   attributes_number LIKE '%status_code%'           (direct reference)
	// Replace these with NULL so the surrounding boolean logic simplifies correctly.
	// Must run BEFORE the :: cast handling below.
	for _, col := range []string{"attributes_number", "attributes_string", "attributes_bool"} {
		// col::Type LIKE '...' → NULL
		q = regexp.MustCompile(`(?i)\b`+col+`::\w+\s+LIKE\s+'[^']*'`).ReplaceAllString(q, "NULL")
		// CAST(col AS Type) LIKE '...' → NULL  (in case :: was already converted)
		q = regexp.MustCompile(`(?i)\bCAST\(`+col+`\s+AS\s+\w+\)\s+LIKE\s+'[^']*'`).ReplaceAllString(q, "NULL")
		// col LIKE '...' → NULL
		q = regexp.MustCompile(`(?i)\b`+col+`\s+LIKE\s+'[^']*'`).ReplaceAllString(q, "NULL")
		// col['key'] → NULL  (map access doesn't work in OpenObserve)
		q = regexp.MustCompile(`(?i)\b`+col+`\['[^']*'\]`).ReplaceAllString(q, "NULL")
		// Any remaining standalone references → NULL
		q = regexp.MustCompile(`(?i)\b`+col+`\b`).ReplaceAllString(q, "NULL")
	}

	// ---- OpenObserve traces field compatibility (must run BEFORE other field replacements) ----

	// ---- Simplify isRoot OR isEntryPoint span search scope ----
	// ClickHouse generates a complex subquery for isEntryPoint that checks against
	// a top_level_operations table. This is extremely slow in OpenObserve (25+ seconds).
	// For practical purposes, checking parent_span_id = '' (root spans) is sufficient.
	// Must run BEFORE parent_span_id → reference_parent_span_id replacement.
	// The pattern has nested parens so [^)]* doesn't work; use .*? instead.
	// In OpenObserve, root spans have reference_parent_span_id as NULL (not empty string).
	// Must use IS NULL OR = '' to catch both cases.
	q = regexp.MustCompile(`(?i)\(parent_span_id\s*=\s*''\s+OR\s+\(.*?AND\s+parent_span_id\s*!=\s*''\)\)`).
		ReplaceAllString(q, "(parent_span_id IS NULL OR parent_span_id = '')")
	// Also handle the case after parent_span_id has been replaced to reference_parent_span_id
	q = regexp.MustCompile(`(?i)\(reference_parent_span_id\s*=\s*''\s+OR\s+\(.*?AND\s+reference_parent_span_id\s*!=\s*''\)\)`).
		ReplaceAllString(q, "(reference_parent_span_id IS NULL OR reference_parent_span_id = '')")

	// kind_string → span_kind (OpenObserve uses span_kind for span kind as string)
	q = regexp.MustCompile(`\bkind_string\b`).ReplaceAllString(q, "span_kind")
	// has_error → (CASE WHEN status_code = 2 THEN 1 ELSE 0 END)
	// OpenObserve doesn't have has_error; derive from status_code (2 = ERROR)
	q = regexp.MustCompile(`\bhas_error\s*=\s*(?:1|true)`).ReplaceAllString(q, "status_code = 2")
	q = regexp.MustCompile(`\bhas_error\s*=\s*(?:0|false)`).ReplaceAllString(q, "status_code != 2")
	q = regexp.MustCompile(`\bhas_error\s*!=\s*(?:0|false)`).ReplaceAllString(q, "status_code = 2")
	q = regexp.MustCompile(`\bhas_error\s*!=\s*(?:1|true)`).ReplaceAllString(q, "status_code != 2")
	// Catch any remaining standalone has_error references
	q = regexp.MustCompile(`\bhas_error\b`).ReplaceAllString(q, "(CASE WHEN status_code = 2 THEN 1 ELSE 0 END)")

	// resource_string_service$$name → service_name (OpenObserve traces have flat service_name)
	q = regexp.MustCompile(`(?i)resource_string_service\$\$name`).ReplaceAllString(q, "service_name")
	// Other resource_string_X$$Y → resource_X_Y (generic fallback)
	q = regexp.MustCompile(`(?i)resource_string_(\w+)\$\$(\w+)`).
		ReplaceAllString(q, "resource_${1}_${2}")

	// response_status_code → http_response_status_code (OpenObserve OTel field name)
	q = regexp.MustCompile(`(?i)\bresponse_status_code\b`).ReplaceAllString(q, "http_response_status_code")

	// ---- PostgreSQL-style :: cast: expr::Type → CAST(expr AS Type) ----
	// Handle chained casts like x::String::Int
	for regexp.MustCompile(`(?i)(\w+(?:\([^)]*\))?)::(\w+)`).MatchString(q) {
		q = regexp.MustCompile(`(?i)(\w+(?:\([^)]*\))?)::(\w+)`).
			ReplaceAllString(q, "CAST($1 AS $2)")
	}

	// ---- Fix dots in alias names: AS alias.name → AS alias_name ----
	// But NOT for __SELECT_KEY_ / __GROUP_BY_KEY_ aliases (already protected above)
	q = regexp.MustCompile(`(?i)\bAS\s+(\w+)\.(\w+)`).
		ReplaceAllString(q, "AS ${1}_${2}")

	// ---- Traces field name mapping ----
	// duration_nano → duration (OpenObserve uses microseconds in 'duration' field)
	q = regexp.MustCompile(`\bduration_nano\b`).ReplaceAllString(q, "duration")
	// serviceName → service_name (in subqueries)
	q = regexp.MustCompile(`\bserviceName\b`).ReplaceAllString(q, "service_name")
	// name → operation_name in traces (OpenObserve uses operation_name for span name)
	// Only replace standalone 'name' not preceded by _ (to keep service_name, operation_name etc)
	q = replaceNameField(q)
	// timestamp → start_time in traces queries (OpenObserve traces use start_time in nanos)
	// Only replace standalone 'timestamp' not preceded by _ (to keep _timestamp)
	q = replaceTimestampField(q)
	// CAST(x AS String) → CAST(x AS VARCHAR) — OpenObserve doesn't know 'String' type
	q = regexp.MustCompile(`(?i)\bAS\s+String\b`).ReplaceAllString(q, "AS VARCHAR")
	// CAST(x AS Float64) → CAST(x AS DOUBLE)
	q = regexp.MustCompile(`(?i)\bAS\s+Float64\b`).ReplaceAllString(q, "AS DOUBLE")
	// CAST(x AS Int64) → CAST(x AS BIGINT)
	q = regexp.MustCompile(`(?i)\bAS\s+Int64\b`).ReplaceAllString(q, "AS BIGINT")
	// CAST(x AS UInt64) → CAST(x AS BIGINT)
	q = regexp.MustCompile(`(?i)\bAS\s+UInt64\b`).ReplaceAllString(q, "AS BIGINT")
	// CAST(x AS UInt32) → CAST(x AS INTEGER)
	q = regexp.MustCompile(`(?i)\bAS\s+UInt32\b`).ReplaceAllString(q, "AS INTEGER")
	// CAST(x AS Int32) → CAST(x AS INTEGER)
	q = regexp.MustCompile(`(?i)\bAS\s+Int32\b`).ReplaceAllString(q, "AS INTEGER")
	// CAST(x AS Float32) → CAST(x AS FLOAT)
	q = regexp.MustCompile(`(?i)\bAS\s+Float32\b`).ReplaceAllString(q, "AS FLOAT")
	// C-style comments // → SQL comments --
	q = strings.ReplaceAll(q, "//", "--")
	// parent_span_id → reference_parent_span_id (OpenObserve uses reference_parent_span_id)
	q = regexp.MustCompile(`(?i)\bparent_span_id\b`).ReplaceAllString(q, "reference_parent_span_id")

	// ---- start_time handling (for traces builder queries) ----
	// OpenObserve traces use _timestamp (microseconds) not start_time (nanoseconds).
	// Convert start_time comparisons to _timestamp with unit conversion.
	// Must run BEFORE the generic 'time' field replacement below.
	q = regexp.MustCompile(`(?i)\bstart_time\s*(>=|<=|>|<|=|!=)\s*'(\d+)'`).
		ReplaceAllStringFunc(q, func(match string) string {
			re := regexp.MustCompile(`(?i)\bstart_time\s*(>=|<=|>|<|=|!=)\s*'(\d+)'`)
			m := re.FindStringSubmatch(match)
			if len(m) < 3 {
				return match
			}
			val := parseInt64(m[2])
			if val > 1e17 {
				val = val / 1000 // nanoseconds → microseconds
			}
			return fmt.Sprintf("_timestamp %s %d", m[1], val)
		})
	q = regexp.MustCompile(`(?i)\bstart_time\s*(>=|<=|>|<|=|!=)\s*(\d+)`).
		ReplaceAllStringFunc(q, func(match string) string {
			re := regexp.MustCompile(`(?i)\bstart_time\s*(>=|<=|>|<|=|!=)\s*(\d+)`)
			m := re.FindStringSubmatch(match)
			if len(m) < 3 {
				return match
			}
			val := parseInt64(m[2])
			if val > 1e17 {
				val = val / 1000
			}
			return fmt.Sprintf("_timestamp %s %d", m[1], val)
		})
	// Replace any remaining standalone start_time with _timestamp
	q = regexp.MustCompile(`(^|[^_\w])\bstart_time\b`).ReplaceAllString(q, "${1}_timestamp")

	// ---- Restore protected __SELECT_KEY_ / __GROUP_BY_KEY_ aliases ----
	// If the alias contains a dot (e.g. __SELECT_KEY_25_service.name),
	// wrap it in double quotes so OpenObserve doesn't interpret the dot
	// as a table.column separator.
	for i, original := range keyAliasPlaceholders {
		placeholder := fmt.Sprintf("__KEYALIAS_PLACEHOLDER_%d__", i)
		restored := original
		if strings.Contains(restored, ".") {
			restored = `"` + restored + `"`
		}
		q = strings.ReplaceAll(q, placeholder, restored)
	}

	// tuple IN: (col1, col2) IN (SELECT ...) → col1 IN (SELECT col1 FROM ...)
	q = replaceTupleIn(q)
	// Fix standalone 'time' field → _timestamp / 1000000
	// ClickHouse uses 'time' as a computed unix timestamp in seconds
	// OpenObserve uses _timestamp in microseconds
	// Only replace when 'time' is followed by a comparison operator to avoid
	// matching metric names like 'system.cpu.time'
	q = regexp.MustCompile(`(^|[^._\w])\btime\b(\s*(?:>=|<=|>|<|=|!=))`).ReplaceAllString(q, "${1}_timestamp / 1000000${2}")

	// ---- multiIf(cond1, val1, cond2, val2, ..., default) → nested CASE WHEN ----
	q = replaceMultiIf(q)

	// ---- mapContains(map, 'key') → column LIKE '%key%' (for stringified JSON maps) ----
	q = replaceFunc(q, "mapContains", func(args string) string {
		parts := splitTopLevelArgs(args)
		if len(parts) >= 2 {
			col := strings.TrimSpace(parts[0])
			key := strings.TrimSpace(parts[1])
			return col + " LIKE '%" + strings.Trim(key, "'\"") + "%'"
		}
		return "1=0"
	})

	// ---- map['key'] → JSON extraction fallback: just return NULL for now ----
	// For OpenObserve flat schema these maps don't exist, so return NULL
	q = regexp.MustCompile(`\b(\w+)\['[^']*'\]`).ReplaceAllString(q, "NULL")

	// ---- accurateCastOrNull(x, 'Type') → TRY_CAST(x AS Type) or CAST(x AS Type) ----
	q = replaceFunc(q, "accurateCastOrNull", func(args string) string {
		parts := splitTopLevelArgs(args)
		if len(parts) >= 2 {
			val := strings.TrimSpace(parts[0])
			typ := strings.Trim(strings.TrimSpace(parts[1]), "'\"")
			return "CAST(" + val + " AS " + typ + ")"
		}
		return "NULL"
	})

	// ---- countIf(cond) → SUM(CASE WHEN cond THEN 1 ELSE 0 END) ----
	q = replaceFunc(q, "countIf", func(args string) string {
		return "SUM(CASE WHEN " + args + " THEN 1 ELSE 0 END)"
	})

	// ---- toFloat64OrNull(x) → CAST(x AS DOUBLE) ----
	q = replaceFunc(q, "toFloat64OrNull", func(args string) string {
		return "CAST(" + args + " AS DOUBLE)"
	})
	q = replaceFunc(q, "toFloat64", func(args string) string {
		return "CAST(" + args + " AS DOUBLE)"
	})
	q = replaceFunc(q, "toInt64OrNull", func(args string) string {
		return "CAST(" + args + " AS BIGINT)"
	})
	q = replaceFunc(q, "toString", func(args string) string {
		return "CAST(" + args + " AS VARCHAR)"
	})

	// ---- PERCENTILE_CONT(N) WITHIN GROUP (ORDER BY x) → keep as-is ----
	// OpenObserve may or may not support this; leave it and see.

	// ---- signoz_metadata.distributed_X → just use the stream name ----
	q = regexp.MustCompile(`(?i)signoz_metadata\.`).ReplaceAllString(q, "")

	// ---- Existing translations (preserved from original) ----

	// Replace JSONExtractKeys(col) → just return the col as JSON keys string
	q = regexp.MustCompile(`(?i)JSONExtractKeys\(([^)]+)\)`).ReplaceAllString(q, "'$1'")

	// Replace toUnixTimestamp(ts) → UNIX_TIMESTAMP(ts)
	q = regexp.MustCompile(`(?i)toUnixTimestamp\(`).ReplaceAllString(q, "UNIX_TIMESTAMP(")

	// Replace toDate(ts) → DATE(ts)
	q = regexp.MustCompile(`(?i)toDate\(`).ReplaceAllString(q, "DATE(")

	// Replace toDateTime(ts) → CAST(ts AS TIMESTAMP)
	q = regexp.MustCompile(`(?i)toDateTime\(`).ReplaceAllString(q, "CAST(")
	q = replaceFuncWithCast(q, "toDateTime")

	// Replace toStartOfInterval(ts, INTERVAL N ...) → DATE_TRUNC(...)
	q = regexp.MustCompile(`(?i)toStartOfInterval\(\s*(\w+)\s*,\s*INTERVAL\s+(\d+)\s+SECOND\s*\)`).
		ReplaceAllString(q, "DATE_TRUNC('second', $1)")
	q = regexp.MustCompile(`(?i)toStartOfInterval\(\s*(\w+)\s*,\s*INTERVAL\s+(\d+)\s+MINUTE\s*\)`).
		ReplaceAllString(q, "DATE_TRUNC('minute', $1)")
	q = regexp.MustCompile(`(?i)toStartOfInterval\(\s*(\w+)\s*,\s*INTERVAL\s+(\d+)\s+HOUR\s*\)`).
		ReplaceAllString(q, "DATE_TRUNC('hour', $1)")
	q = regexp.MustCompile(`(?i)toStartOfInterval\(\s*(\w+)\s*,\s*INTERVAL\s+(\d+)\s+DAY\s*\)`).
		ReplaceAllString(q, "DATE_TRUNC('day', $1)")

	q = regexp.MustCompile(`(?i)toStartOfMinute\(\s*(\w+)\s*\)`).
		ReplaceAllString(q, "DATE_TRUNC('minute', $1)")
	q = regexp.MustCompile(`(?i)toStartOfFiveMinutes\(\s*(\w+)\s*\)`).
		ReplaceAllString(q, "DATE_TRUNC('minute', $1)")
	q = regexp.MustCompile(`(?i)toStartOfFifteenMinutes\(\s*(\w+)\s*\)`).
		ReplaceAllString(q, "DATE_TRUNC('minute', $1)")
	q = regexp.MustCompile(`(?i)toStartOfHour\(\s*(\w+)\s*\)`).
		ReplaceAllString(q, "DATE_TRUNC('hour', $1)")
	q = regexp.MustCompile(`(?i)toStartOfDay\(\s*(\w+)\s*\)`).
		ReplaceAllString(q, "DATE_TRUNC('day', $1)")

	// Replace ts_bucket_start → (_timestamp / 1000000)
	q = strings.ReplaceAll(q, "ts_bucket_start", "(_timestamp / 1000000)")

	// quantile(N)(x) → PERCENTILE_CONT(N) WITHIN GROUP (ORDER BY x)
	q = replaceQuantile(q)

	// cityHash64(x) → ABS(HASH_CODE(x)
	q = regexp.MustCompile(`(?i)cityHash64\(`).ReplaceAllString(q, "ABS(HASH_CODE(")

	// if(cond, a, b) → CASE WHEN cond THEN a ELSE b END
	q = replaceIfFunction(q)

	// Cast functions
	q = replaceCastFunc(q, "toUInt64", "BIGINT")
	q = replaceCastFunc(q, "toInt64", "BIGINT")
	q = replaceCastFunc(q, "toUInt32", "INTEGER")
	q = replaceCastFunc(q, "toInt32", "INTEGER")
	q = replaceCastFunc(q, "toFloat64", "DOUBLE")
	q = replaceCastFunc(q, "toFloat32", "FLOAT")
	q = replaceCastFunc(q, "toString", "VARCHAR")

	q = regexp.MustCompile(`(?i)fromUnixTimestamp64Nano\(\s*(\w+)\s*\)`).
		ReplaceAllString(q, "TO_TIMESTAMP($1 / 1000000000)")
	q = regexp.MustCompile(`(?i)fromUnixTimestamp\(`).ReplaceAllString(q, "TO_TIMESTAMP(")
	q = regexp.MustCompile(`(?i)toDateTime64\(\s*([^,)]+)(?:,\s*\d+)?\s*\)`).
		ReplaceAllString(q, "CAST($1 AS TIMESTAMP)")

	q = regexp.MustCompile(`(?i)arrayJoin\(\s*(\w+)\s*\)`).ReplaceAllString(q, "$1")
	q = regexp.MustCompile(`(?i)\bcount\(\)`).ReplaceAllString(q, "COUNT(*)")

	// ---- OpenObserve field compatibility fixes ----
	// resources_string doesn't exist in OpenObserve; make LIKE conditions always false
	q = regexp.MustCompile(`(?i)resources_string\s+LIKE\s+'[^']*'`).ReplaceAllString(q, "1=0")
	// attributes_string/attributes_number/attributes_bool → '{}' (empty JSON) for queries that SELECT them
	// These fields don't exist as separate maps in OpenObserve flat schema

	// ---- Final pass: replace any ClickHouse type names introduced by later transformations ----
	// (e.g. accurateCastOrNull may produce CAST(x AS Float64) after the initial type replacement)
	q = regexp.MustCompile(`(?i)\bAS\s+Float64\b`).ReplaceAllString(q, "AS DOUBLE")
	q = regexp.MustCompile(`(?i)\bAS\s+Float32\b`).ReplaceAllString(q, "AS FLOAT")
	q = regexp.MustCompile(`(?i)\bAS\s+Int64\b`).ReplaceAllString(q, "AS BIGINT")
	q = regexp.MustCompile(`(?i)\bAS\s+UInt64\b`).ReplaceAllString(q, "AS BIGINT")
	q = regexp.MustCompile(`(?i)\bAS\s+Int32\b`).ReplaceAllString(q, "AS INTEGER")
	q = regexp.MustCompile(`(?i)\bAS\s+UInt32\b`).ReplaceAllString(q, "AS INTEGER")
	q = regexp.MustCompile(`(?i)\bAS\s+String\b`).ReplaceAllString(q, "AS VARCHAR")

	// ---- Fix incomplete CAST expressions: CAST(expr) without AS type → just expr ----
	// OpenObserve parser fails with 'unknown function cast' when CAST lacks AS type
	castRe := regexp.MustCompile(`(?i)\bCAST\(([^()]+)\)`)
	asRe := regexp.MustCompile(`(?i)\bAS\b`)
	q = castRe.ReplaceAllStringFunc(q, func(match string) string {
		inner := castRe.FindStringSubmatch(match)[1]
		if asRe.MatchString(inner) {
			return match // has AS type, keep as-is
		}
		return strings.TrimSpace(inner) // no AS type, unwrap to just the expression
	})

	// ---- Remove ClickHouse LIMIT N BY syntax ----
	// OpenObserve doesn't support LIMIT N BY col; just strip it.
	q = regexp.MustCompile(`(?i)\bLIMIT\s+\d+\s+BY\s+[\w.,\s]+`).ReplaceAllString(q, "")

	// ---- Fix SELECT * in subqueries ----
	// OpenObserve parser fails with "Expected: joined table, found: *" for SELECT * in subqueries.
	// Replace with explicit column references for traces/logs streams.
	q = regexp.MustCompile(`(?i)\bSELECT\s+\*\s+FROM\s+\(\s*SELECT\b`).ReplaceAllString(q,
		"SELECT traceID, durationNano, service_name, operation_name, _timestamp, span_id, reference_parent_span_id, status_code FROM (SELECT")

	// ---- Convert nanosecond timestamps to microseconds ----
	// ClickHouse uses nanoseconds; OpenObserve _timestamp is in microseconds.
	q = convertNanosecondTimestamps(q)

	return q
}

// replaceMultiIf converts multiIf(cond1, val1, cond2, val2, ..., default)
// into nested CASE WHEN expressions.
func replaceMultiIf(query string) string {
	return replaceFunc(query, "multiIf", func(args string) string {
		parts := splitTopLevelArgs(args)
		if len(parts) < 2 {
			return args
		}
		var sb strings.Builder
		sb.WriteString("CASE")
		i := 0
		for i+1 < len(parts) {
			cond := parts[i]
			val := parts[i+1]
			sb.WriteString(" WHEN ")
			sb.WriteString(cond)
			sb.WriteString(" THEN ")
			sb.WriteString(val)
			i += 2
		}
		if i < len(parts) {
			sb.WriteString(" ELSE ")
			sb.WriteString(parts[i])
		}
		sb.WriteString(" END")
		return sb.String()
	})
}

// replaceTupleIn converts ClickHouse tuple IN syntax to standard SQL.
// (col1, col2) IN (SELECT col1, col2 FROM ...) → col1 IN (SELECT col1 FROM ...)
func replaceTupleIn(query string) string {
	// Match the tuple IN prefix: (col1, col2) IN (SELECT [DISTINCT] col3, col4
	// and convert to: col1 IN (SELECT col3
	// This leaves the FROM ... part intact, avoiding issues with nested parentheses
	re := regexp.MustCompile(`(?i)\((\w+)\s*,\s*\w+\)\s+IN\s*\(\s*SELECT\s+(?:DISTINCT\s+)?(\w+)\s*,\s*\w+`)
	return re.ReplaceAllString(query, "$1 IN (SELECT $2")
}

// replaceNameField replaces standalone 'name' with 'operation_name' but preserves
// compound identifiers like service_name, operation_name, etc.
// Go RE2 doesn't support lookbehind, so we capture the preceding character.
func replaceNameField(q string) string {
	// Match a non-underscore/non-word char followed by 'name' at word boundary
	re := regexp.MustCompile(`(^|[^_\w])\bname\b`)
	return re.ReplaceAllString(q, "${1}operation_name")
}

// replaceTimestampField replaces standalone 'timestamp' with '_timestamp' but preserves
// '_timestamp' and other compound identifiers ending in 'timestamp'.
// In OpenObserve traces, _timestamp (microseconds) is the primary time field.
func replaceTimestampField(q string) string {
	// Match 'timestamp' NOT preceded by any word char or underscore
	// This preserves _timestamp, start_timestamp, etc.
	re := regexp.MustCompile(`(^|[^_\w])\btimestamp\b`)
	return re.ReplaceAllString(q, "${1}_timestamp")
}

// rewriteTableReferences replaces ALL table references in SQL with the
// target OpenObserve stream name.
func rewriteTableReferences(query string, targetStream string) string {
	if targetStream == "" {
		return query
	}

	q := query

	// Replace known database-prefixed table references
	knownPrefixes := []string{
		"signoz_traces.", "signoz_metrics.", "signoz_logs.",
		"signoz_metadata.", "default.",
	}
	for _, prefix := range knownPrefixes {
		pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(prefix) + `[\w]+`)
		q = pattern.ReplaceAllString(q, `"`+targetStream+`"`)
	}

	// Replace remaining quoted table names that are known ClickHouse tables
	// (these appear in FROM clauses after the database prefix was already stripped)
	knownTables := []string{
		"distributed_signoz_index_v3", "signoz_index_v3", "signoz_index_v2",
		"distributed_signoz_index_v2", "signoz_spans", "distributed_signoz_spans",
		"distributed_logs_v2", "logs_v2", "distributed_logs",
		"distributed_tag_attributes_v2", "tag_attributes_v2",
		"distributed_tag_attributes", "tag_attributes",
		"distributed_metadata", "metadata",
		"distributed_column_evolution_metadata", "column_evolution_metadata",
		"distributed_span_attributes_keys", "span_attributes_keys",
		"distributed_log_attribute_keys", "log_attribute_keys",
		"distributed_log_resource_keys", "log_resource_keys",
		"distributed_audit_logs", "audit_logs",
		"distributed_samples_v2", "samples_v2",
		"distributed_time_series_v2", "time_series_v2",
		"distributed_trace_summary", "trace_summary",
	}
	for _, table := range knownTables {
		// Replace both quoted and unquoted references
		q = strings.ReplaceAll(q, `"`+table+`"`, `"`+targetStream+`"`)
		// Unquoted (but word-boundary matched to avoid partial replacements)
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(table) + `\b`)
		q = re.ReplaceAllString(q, `"`+targetStream+`"`)
	}

	return q
}

// replaceQuantile converts ClickHouse quantile(N)(x) to standard SQL PERCENTILE_CONT.
func replaceQuantile(query string) string {
	re := regexp.MustCompile(`(?i)quantile\((\d+\.?\d*)\)\(\s*([^)]+)\s*\)`)
	return re.ReplaceAllString(query, "PERCENTILE_CONT($1) WITHIN GROUP (ORDER BY $2)")
}

// replaceIfFunction converts if(cond, a, b) to CASE WHEN cond THEN a ELSE b END.
// This is a simplified version that handles basic cases.
func replaceIfFunction(query string) string {
	re := regexp.MustCompile(`(?i)\bif\(\s*([^,]+),\s*([^,]+),\s*([^)]+)\)`)
	return re.ReplaceAllString(query, "CASE WHEN $1 THEN $2 ELSE $3 END")
}

// replaceCastFunc converts ClickHouse cast functions to standard SQL CAST.
func replaceCastFunc(query, funcName, sqlType string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?i)%s\(\s*([^)]+)\)`, regexp.QuoteMeta(funcName)))
	return re.ReplaceAllString(query, fmt.Sprintf("CAST($1 AS %s)", sqlType))
}

// replaceFuncWithCast converts funcName(x) to CAST(x AS TIMESTAMP).
func replaceFuncWithCast(query, funcName string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?i)%s\(\s*([^)]+)\)`, regexp.QuoteMeta(funcName)))
	return re.ReplaceAllString(query, "CAST($1 AS TIMESTAMP)")
}

// convertNanosecondTimestamps converts nanosecond timestamp literal values (>1e15)
// to microseconds in SQL WHERE clause comparisons with _timestamp.
// OpenObserve _timestamp is in microseconds, but ClickHouse uses nanoseconds.
// Also removes quotes around numeric literals since OpenObserve _timestamp is numeric.
func convertNanosecondTimestamps(q string) string {
	// Pattern 1: _timestamp OP 'large_number' (quoted string literal)
	// Convert nanosecond values to microseconds and remove quotes.
	q = regexp.MustCompile(`(?i)(_timestamp\s*(?:>=|<=|>|<|=|!=)\s*)'([0-9]{16,})'`).
		ReplaceAllStringFunc(q, func(match string) string {
			re := regexp.MustCompile(`(?i)(_timestamp\s*(?:>=|<=|>|<|=|!=)\s*)'([0-9]{16,})'`)
			m := re.FindStringSubmatch(match)
			if len(m) < 3 {
				return match
			}
			val := parseInt64(m[2])
			if val > 1e18 {
				return fmt.Sprintf("%s%d", m[1], val/1000)
			}
			// Even if not nanoseconds, remove quotes for numeric comparison
			return fmt.Sprintf("%s%s", m[1], m[2])
		})

	// Pattern 2: _timestamp OP large_number (unquoted numeric literal)
	// Only convert nanosecond values (19+ digits, > 1e18)
	q = regexp.MustCompile(`(?i)(_timestamp\s*(?:>=|<=|>|<|=|!=)\s*)([0-9]{16,})\b`).
		ReplaceAllStringFunc(q, func(match string) string {
			re := regexp.MustCompile(`(?i)(_timestamp\s*(?:>=|<=|>|<|=|!=)\s*)([0-9]{16,})\b`)
			m := re.FindStringSubmatch(match)
			if len(m) < 3 {
				return match
			}
			val := parseInt64(m[2])
			if val > 1e18 {
				return fmt.Sprintf("%s%d", m[1], val/1000)
			}
			return match
		})

	return q
}

// interpolateArgs replaces ? placeholders, $N positional parameters, and @named parameters
// with the actual argument values.
// OpenObserve SQL API does not support parameterized queries, so we inline values.
// Supports positional (?), ClickHouse-style ($1, $2), and named (@name) parameters,
// including clickhouse.Named structs.
func interpolateArgs(query string, args ...any) string {
	if len(args) == 0 {
		return query
	}

	result := query

	// First pass: handle clickhouse.Named parameters (@name style)
	for _, arg := range args {
		if arg == nil {
			continue
		}
		rv := reflect.ValueOf(arg)
		if rv.Kind() == reflect.Struct {
			nameField := rv.FieldByName("Name")
			valueField := rv.FieldByName("Value")
			if nameField.IsValid() && nameField.Kind() == reflect.String && valueField.IsValid() {
				name := nameField.String()
				val := formatArgValue(valueField.Interface())
				result = strings.ReplaceAll(result, "@"+name, val)
			}
		}
	}

	// Second pass: handle positional ? placeholders
	for _, arg := range args {
		if arg == nil {
			continue
		}
		// Skip named parameters (already handled)
		rv := reflect.ValueOf(arg)
		if rv.Kind() == reflect.Struct {
			if rv.FieldByName("Name").IsValid() && rv.FieldByName("Value").IsValid() {
				continue
			}
		}
		val := formatArgValue(arg)
		result = strings.Replace(result, "?", val, 1)
	}

	// Third pass: handle ClickHouse-style $1, $2, ... placeholders
	// Collect non-named positional args in order
	var positionalArgs []any
	for _, arg := range args {
		if arg == nil {
			positionalArgs = append(positionalArgs, nil)
			continue
		}
		rv := reflect.ValueOf(arg)
		if rv.Kind() == reflect.Struct {
			if rv.FieldByName("Name").IsValid() && rv.FieldByName("Value").IsValid() {
				continue // skip named parameters
			}
		}
		positionalArgs = append(positionalArgs, arg)
	}
	for i, arg := range positionalArgs {
		placeholder := fmt.Sprintf("$%d", i+1)
		if strings.Contains(result, placeholder) {
			val := formatArgValue(arg)
			result = strings.ReplaceAll(result, placeholder, val)
		}
	}

	return result
}

// formatArgValue formats a Go value as a SQL literal.
func formatArgValue(arg any) string {
	if arg == nil {
		return "NULL"
	}
	switch v := arg.(type) {
	case time.Time:
		return fmt.Sprintf("'%d'", v.UnixNano())
	case string:
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%v", v)
	case bool:
		if v {
			return "1"
		}
		return "0"
	case []string:
		parts := make([]string, len(v))
		for i, s := range v {
			parts[i] = "'" + strings.ReplaceAll(s, "'", "''") + "'"
		}
		return "(" + strings.Join(parts, ",") + ")"
	case []int, []int64, []uint64:
		rv := reflect.ValueOf(arg)
		parts := make([]string, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			parts[i] = fmt.Sprintf("%d", rv.Index(i).Interface())
		}
		return "(" + strings.Join(parts, ",") + ")"
	default:
		// Check for time.Time via reflection (in case it's wrapped)
		rv := reflect.ValueOf(arg)
		if rv.Type() == reflect.TypeOf(time.Time{}) {
			t := rv.Interface().(time.Time)
			return fmt.Sprintf("'%d'", t.UnixNano())
		}
		// Handle slices via reflection
		if rv.Kind() == reflect.Slice {
			parts := make([]string, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				elem := rv.Index(i).Interface()
				switch ev := elem.(type) {
				case string:
					parts[i] = "'" + strings.ReplaceAll(ev, "'", "''") + "'"
				default:
					parts[i] = fmt.Sprintf("%v", ev)
				}
			}
			return "(" + strings.Join(parts, ",") + ")"
		}
		return fmt.Sprintf("'%v'", v)
	}
}
