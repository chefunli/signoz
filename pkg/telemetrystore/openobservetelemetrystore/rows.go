package openobservetelemetrystore

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SigNoz/signoz/pkg/telemetrystore"
)

// ooResponse represents the OpenOberve search API response.
type ooResponse struct {
	Hits        []map[string]any `json:"hits"`
	Total       int              `json:"total"`
	columnOrder []string         // expected column order extracted from SQL
}

// ooRows implements telemetrystore.Rows for OpenObserve JSON responses.
type ooRows struct {
	hits    []map[string]any
	columns []string
	pos     int
	closed  bool
}

func newOORows(resp *ooResponse) *ooRows {
	var columns []string
	if len(resp.columnOrder) > 0 {
		// Use SQL-defined column order, matching to actual response keys
		columns = matchColumnOrder(resp.columnOrder, resp.Hits)
	}
	if len(columns) == 0 {
		columns = extractColumns(resp.Hits)
	}
	return &ooRows{
		hits:    resp.Hits,
		columns: columns,
		pos:     -1,
	}
}

func (r *ooRows) Next() bool {
	if r.closed || r.pos >= len(r.hits)-1 {
		return false
	}
	r.pos++
	return true
}

func (r *ooRows) Scan(dest ...any) error {
	if r.pos < 0 || r.pos >= len(r.hits) {
		return fmt.Errorf("scan: invalid row position %d", r.pos)
	}
	hit := r.hits[r.pos]

	for i, d := range dest {
		if i >= len(r.columns) {
			break
		}
		colName := r.columns[i]
		val, ok := hit[colName]
		if !ok {
			// Try case-insensitive match
			val, ok = hitCaseInsensitive(hit, colName)
		}
		if err := assignValue(d, val); err != nil {
			return fmt.Errorf("scan column %q: %w", colName, err)
		}
	}
	return nil
}

func (r *ooRows) Close() error {
	r.closed = true
	return nil
}

func (r *ooRows) Err() error {
	return nil
}

func (r *ooRows) Columns() ([]string, error) {
	return r.columns, nil
}

func (r *ooRows) ColumnTypes() ([]telemetrystore.ColumnType, error) {
	types := make([]telemetrystore.ColumnType, len(r.columns))
	for i, col := range r.columns {
		// For timestamp columns, always return time.Time scan type
		// regardless of the actual value type, because SigNoz expects time.Time.
		if strings.ToLower(col) == "timestamp" || strings.ToLower(col) == "ts" {
			types[i] = &ooColumnType{
				name:     col,
				dbType:   "DateTime64(9)",
				scanType: reflect.TypeOf(time.Time{}),
			}
		} else {
			dbType := inferDBType(r.hits, col)
			types[i] = &ooColumnType{
				name:     col,
				dbType:   dbType,
				scanType: dbTypeToGoType(dbType),
			}
		}
	}
	return types, nil
}

// ooColumnType implements telemetrystore.ColumnType for OpenObserve.
type ooColumnType struct {
	name     string
	dbType   string
	scanType reflect.Type
}

func (c *ooColumnType) Name() string             { return c.name }
func (c *ooColumnType) DatabaseTypeName() string { return c.dbType }
func (c *ooColumnType) ScanType() reflect.Type   { return c.scanType }

// ooRow implements telemetrystore.Row for OpenObserve (single row).
type ooRow struct {
	hit  map[string]any
	cols []string
	err  error
}

func newOORow(hit map[string]any) *ooRow {
	cols := make([]string, 0, len(hit))
	for k := range hit {
		cols = append(cols, k)
	}
	return &ooRow{hit: hit, cols: cols}
}

// newOORowWithOrder creates an ooRow with a specific column order from SQL.
func newOORowWithOrder(hit map[string]any, columnOrder []string) *ooRow {
	var cols []string
	if len(columnOrder) > 0 {
		cols = matchColumnOrder(columnOrder, []map[string]any{hit})
	}
	if len(cols) == 0 {
		cols = make([]string, 0, len(hit))
		for k := range hit {
			cols = append(cols, k)
		}
	}
	return &ooRow{hit: hit, cols: cols}
}

func (r *ooRow) Scan(dest ...any) error {
	for i, d := range dest {
		if i >= len(r.cols) {
			break
		}
		colName := r.cols[i]
		val := r.hit[colName]
		if err := assignValue(d, val); err != nil {
			return fmt.Errorf("scan column %q: %w", colName, err)
		}
	}
	return nil
}

func (r *ooRow) ScanStruct(dest any) error {
	v := reflect.ValueOf(dest)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("ScanStruct: dest must be a non-nil pointer")
	}
	elem := v.Elem()
	if elem.Kind() != reflect.Struct {
		return fmt.Errorf("ScanStruct: dest must point to a struct")
	}
	t := elem.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldVal := elem.Field(i)
		if !fieldVal.CanSet() {
			continue
		}

		// Try JSON tag first, then field name
		colName := field.Tag.Get("json")
		if colName == "" || colName == "-" {
			colName = field.Name
		}
		// Strip omitempty etc.
		if idx := strings.Index(colName, ","); idx >= 0 {
			colName = colName[:idx]
		}

		val, ok := r.hit[colName]
		if !ok {
			val, ok = hitCaseInsensitive(r.hit, colName)
		}
		if !ok {
			continue
		}

		if err := assignReflectValue(fieldVal, val); err != nil {
			return fmt.Errorf("scan field %q: %w", field.Name, err)
		}
	}
	return nil
}

func (r *ooRow) Err() error {
	return r.err
}

// ooBatch implements telemetrystore.Batch as a no-op (OpenObserve handles ingestion).
type ooBatch struct{}

func (b *ooBatch) Append(v ...any) error { return nil }
func (b *ooBatch) Send() error           { return nil }
func (b *ooBatch) Abort() error          { return nil }
func (b *ooBatch) Close() error          { return nil }

// --- helpers ---

// extractColumnOrderFromSQL parses the SELECT clause of a SQL query to determine
// the expected column order. Returns alias names (or column expressions) in order.
func extractColumnOrderFromSQL(sql string) []string {
	// Find SELECT ... FROM boundaries
	selectRe := regexp.MustCompile(`(?is)^\s*SELECT\s+(?:DISTINCT\s+)?(.+?)\s+FROM\b`)
	m := selectRe.FindStringSubmatch(sql)
	if len(m) < 2 {
		return nil
	}
	selectClause := m[1]
	// Clean up any trailing quotes or whitespace from the FROM boundary
	selectClause = strings.TrimRight(selectClause, "\"'` \t\n\r")

	// Split by top-level commas (respecting parentheses and quotes)
	items := splitSelectItems(selectClause)

	var columns []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || item == "*" {
			continue
		}
		// Look for alias: AS "alias" or AS alias
		aliasRe := regexp.MustCompile(`(?i)\s+AS\s+(?:"([^"]+)"|'([^']+)'|(\w+))\s*$`)
		if am := aliasRe.FindStringSubmatch(item); len(am) > 1 {
			for _, g := range am[1:] {
				if g != "" {
					columns = append(columns, g)
					break
				}
			}
			continue
		}
		// No alias - use the column name itself
		// Handle expressions like MAX(_timestamp) → skip, or simple column names
		item = strings.TrimSpace(item)
		// Remove function wrappers: MAX(x) → use the whole expression as name
		// For simple column references, use as-is
		if !strings.Contains(item, "(") {
			columns = append(columns, item)
		}
	}
	return columns
}

// splitSelectItems splits a SELECT clause by top-level commas,
// respecting parentheses and single-quoted string literals.
func splitSelectItems(s string) []string {
	var items []string
	depth := 0
	inQuote := false
	start := 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\'' && !inQuote:
			inQuote = true
		case s[i] == '\'' && inQuote:
			inQuote = false
		case s[i] == '(' && !inQuote:
			depth++
		case s[i] == ')' && !inQuote:
			depth--
		case s[i] == ',' && depth == 0 && !inQuote:
			items = append(items, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		items = append(items, s[start:])
	}
	return items
}

// matchColumnOrder maps SQL-defined column order to actual response keys,
// using case-insensitive matching since OpenObserve lowercases aliases.
func matchColumnOrder(sqlColumns []string, hits []map[string]any) []string {
	if len(hits) == 0 || len(sqlColumns) == 0 {
		return nil
	}
	// Build a set of actual keys (from first hit)
	actualKeys := make(map[string]bool)
	for k := range hits[0] {
		actualKeys[k] = true
	}

	var ordered []string
	used := make(map[string]bool)
	for _, sqlCol := range sqlColumns {
		// Try exact match first
		if actualKeys[sqlCol] && !used[sqlCol] {
			ordered = append(ordered, sqlCol)
			used[sqlCol] = true
			continue
		}
		// Try case-insensitive match
		sqlLower := strings.ToLower(sqlCol)
		for k := range actualKeys {
			if strings.ToLower(k) == sqlLower && !used[k] {
				ordered = append(ordered, k)
				used[k] = true
				break
			}
		}
	}

	// Add any remaining keys not covered by SQL order
	for k := range actualKeys {
		if !used[k] {
			ordered = append(ordered, k)
		}
	}

	if len(ordered) == 0 {
		return nil
	}
	return ordered
}

func extractColumns(hits []map[string]any) []string {
	if len(hits) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var cols []string
	for _, hit := range hits {
		for k := range hit {
			if !seen[k] {
				seen[k] = true
				cols = append(cols, k)
			}
		}
	}
	return cols
}

func hitCaseInsensitive(hit map[string]any, key string) (any, bool) {
	lower := strings.ToLower(key)
	for k, v := range hit {
		if strings.ToLower(k) == lower {
			return v, true
		}
	}
	return nil, false
}

// addTagMapping adds the field's json: or ch: tag to the tagMap.
// Prefers json: tag, falls back to ch: tag, then field name.
func addTagMapping(tagMap map[string]string, field reflect.StructField) {
	jsonTag := field.Tag.Get("json")
	chTag := field.Tag.Get("ch")

	jsonName := ""
	if jsonTag != "" && jsonTag != "-" {
		jsonName = strings.Split(jsonTag, ",")[0]
	}

	chName := ""
	if chTag != "" && chTag != "-" {
		chName = strings.Split(chTag, ",")[0]
	}

	// json.Unmarshal uses json: tag if present, otherwise matches field name.
	// We need to map ch: tag names (from SQL aliases / OpenObserve response keys)
	// to the names that json.Unmarshal will look for.
	if jsonName != "" {
		tagMap[strings.ToLower(jsonName)] = jsonName
		if chName != "" && chName != jsonName {
			// ch: name differs from json: name — map ch: → json:
			tagMap[strings.ToLower(chName)] = jsonName
		}
	} else if chName != "" {
		// No json: tag — json.Unmarshal matches by field name (case-insensitive)
		tagMap[strings.ToLower(chName)] = field.Name
	}
}

// normalizeHitKeys fixes the case mismatch between OpenObserve's lowercased
// response keys and the struct's JSON tags.
// OpenObserve lowercases all SQL aliases (e.g. "serviceName" → "servicename").
// This function renames hit keys to match the struct's JSON tag names so that
// json.Unmarshal can correctly map them.
func normalizeHitKeys(hits []map[string]any, dest interface{}) {
	if len(hits) == 0 {
		return
	}

	// Determine the element type of the destination slice
	destType := reflect.TypeOf(dest)
	if destType.Kind() == reflect.Ptr {
		destType = destType.Elem()
	}
	if destType.Kind() != reflect.Slice {
		return
	}
	elemType := destType.Elem()
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}
	if elemType.Kind() != reflect.Struct {
		return
	}

	// Build mapping: lowercase(tag) → original tag name
	// Check both json: and ch: tags since some structs use ch: instead of json:
	tagMap := make(map[string]string)
	for i := 0; i < elemType.NumField(); i++ {
		field := elemType.Field(i)
		// Handle embedded structs
		if field.Anonymous {
			ft := field.Type
			if ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for j := 0; j < ft.NumField(); j++ {
					addTagMapping(tagMap, ft.Field(j))
				}
			}
			continue
		}
		addTagMapping(tagMap, field)
	}

	if len(tagMap) == 0 {
		return
	}

	// Rename keys in each hit
	for _, hit := range hits {
		var toAdd map[string]any
		var toRemove []string
		for k := range hit {
			lower := strings.ToLower(k)
			if original, ok := tagMap[lower]; ok && k != original {
				if toAdd == nil {
					toAdd = make(map[string]any)
				}
				toAdd[original] = hit[k]
				toRemove = append(toRemove, k)
			}
		}
		for _, k := range toRemove {
			delete(hit, k)
		}
		for k, v := range toAdd {
			hit[k] = v
		}
	}
}

// coerceHitStringsToJSON converts string values in hits based on the target struct field types.
// - JSON object/array strings → map/slice (only when target field is map/slice)
// - Numeric strings → float64 (only when target field is numeric)
// - Boolean strings → bool (only when target field is bool)
// - Numeric timestamps → RFC3339 strings (for time.Time fields)
// This is needed because OpenObserve returns all values as strings, but Go structs
// expect specific types. Fields that are string type in the struct are left as strings.
func coerceHitStringsToJSON(hits []map[string]any, dest interface{}) {
	if len(hits) == 0 {
		return
	}

	// Build maps of field name → field type info from the destination struct
	fieldKinds := buildFieldKindMap(dest)
	timeFields := buildTimeFieldSet(dest)
	sliceElemKinds := buildSliceElemKindMap(dest)

	for _, hit := range hits {
		for k, v := range hit {
			lowerKey := strings.ToLower(k)

			// Handle time.Time fields: convert numeric timestamps to RFC3339 strings
			if timeFields[lowerKey] {
				switch tv := v.(type) {
				case float64:
					hit[k] = floatToTimeStr(tv)
				case int64:
					hit[k] = floatToTimeStr(float64(tv))
				case string:
					// If it's a numeric string, parse and convert
					trimmed := strings.TrimSpace(tv)
					if isNumericString(trimmed) {
						if f, err := strconv.ParseFloat(trimmed, 64); err == nil {
							hit[k] = floatToTimeStr(f)
						}
					}
				}
				continue
			}

			s, ok := v.(string)
			if !ok {
				continue
			}
			trimmed := strings.TrimSpace(s)
			if len(trimmed) < 1 {
				continue
			}

			// Look up the target field type
			targetKind, hasField := fieldKinds[lowerKey]

			// Try JSON objects/arrays only if target field is map or slice
			if len(trimmed) >= 2 {
				if (trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}') ||
					(trimmed[0] == '[' && trimmed[len(trimmed)-1] == ']') {
					if targetKind == reflect.Map || targetKind == reflect.Slice || targetKind == reflect.Array {
						// Special handling for []string targets (e.g. SpanItemV2.Events):
						// Parse the JSON array and re-encode each element as a JSON string.
						// This handles both Array(Object) and Array(String) source data.
						elemKind, hasElemKind := sliceElemKinds[lowerKey]
						if hasElemKind && elemKind == reflect.String && trimmed[0] == '[' {
							var arr []any
							if err := json.Unmarshal([]byte(trimmed), &arr); err == nil {
								strs := make([]string, len(arr))
								for j, elem := range arr {
									b, _ := json.Marshal(elem)
									strs[j] = string(b)
								}
								hit[k] = strs
								continue
							}
							// If parsing failed, fall through to generic handling
						}
						var parsed any
						if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil {
							hit[k] = parsed
							continue
						}
					}
					// If target is string or unknown, leave as-is
					if targetKind == reflect.String || !hasField {
						continue
					}
				}
			}

			// Convert boolean strings only if target field is bool
			if targetKind == reflect.Bool {
				if trimmed == "true" {
					hit[k] = true
					continue
				}
				if trimmed == "false" {
					hit[k] = false
					continue
				}
			}

			// Convert numeric strings only if target field is numeric
			if isNumericKind(targetKind) && isNumericString(trimmed) {
				if f, err := strconv.ParseFloat(trimmed, 64); err == nil {
					hit[k] = f
				}
			}
		}
	}
}

// buildTimeFieldSet returns a set of lowercase field names that are time.Time type.
func buildTimeFieldSet(dest interface{}) map[string]bool {
	result := make(map[string]bool)
	timeType := reflect.TypeOf(time.Time{})

	destType := reflect.TypeOf(dest)
	if destType.Kind() == reflect.Ptr {
		destType = destType.Elem()
	}
	if destType.Kind() != reflect.Slice {
		return result
	}
	elemType := destType.Elem()
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}
	if elemType.Kind() != reflect.Struct {
		return result
	}

	for i := 0; i < elemType.NumField(); i++ {
		field := elemType.Field(i)
		if field.Anonymous {
			continue
		}
		if field.Type == timeType {
			tag := field.Tag.Get("json")
			if tag == "" || tag == "-" {
				tag = field.Tag.Get("ch")
			}
			if tag != "" && tag != "-" {
				name := strings.Split(tag, ",")[0]
				result[strings.ToLower(name)] = true
			}
			// Also add the Go field name so that keys renamed by normalizeHitKeys
			// (from ch: tag → Go field name) are still recognized as time fields.
			result[strings.ToLower(field.Name)] = true
		}
	}
	return result
}

// buildFieldKindMap creates a map of lowercase field name → reflect.Kind from a struct.
// Supports json: and ch: tags, and handles embedded structs.
func buildFieldKindMap(dest interface{}) map[string]reflect.Kind {
	result := make(map[string]reflect.Kind)

	destType := reflect.TypeOf(dest)
	if destType.Kind() == reflect.Ptr {
		destType = destType.Elem()
	}
	if destType.Kind() != reflect.Slice {
		return result
	}
	elemType := destType.Elem()
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}
	if elemType.Kind() != reflect.Struct {
		return result
	}

	for i := 0; i < elemType.NumField(); i++ {
		field := elemType.Field(i)
		// Handle embedded structs
		if field.Anonymous {
			ft := field.Type
			if ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for j := 0; j < ft.NumField(); j++ {
					addFieldKind(result, ft.Field(j))
				}
			}
			continue
		}
		addFieldKind(result, field)
	}
	return result
}

func addFieldKind(m map[string]reflect.Kind, field reflect.StructField) {
	tag := field.Tag.Get("json")
	if tag == "" || tag == "-" {
		tag = field.Tag.Get("ch")
	}
	if tag == "" || tag == "-" {
		return
	}
	name := strings.Split(tag, ",")[0]
	m[strings.ToLower(name)] = field.Type.Kind()
}

// buildSliceElemKindMap creates a map of lowercase field name → slice element reflect.Kind.
// Only includes fields whose type is a slice or array.
func buildSliceElemKindMap(dest interface{}) map[string]reflect.Kind {
	result := make(map[string]reflect.Kind)

	destType := reflect.TypeOf(dest)
	if destType.Kind() == reflect.Ptr {
		destType = destType.Elem()
	}
	if destType.Kind() != reflect.Slice {
		return result
	}
	elemType := destType.Elem()
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}
	if elemType.Kind() != reflect.Struct {
		return result
	}

	for i := 0; i < elemType.NumField(); i++ {
		field := elemType.Field(i)
		if field.Anonymous {
			continue
		}
		ft := field.Type
		if ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
			tag := field.Tag.Get("json")
			if tag == "" || tag == "-" {
				tag = field.Tag.Get("ch")
			}
			if tag == "" || tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			result[strings.ToLower(name)] = ft.Elem().Kind()
		}
	}
	return result
}

// isNumericKind returns true if the reflect.Kind is a numeric type.
func isNumericKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// isNumericString checks if a string represents a plain number (integer or float).
func isNumericString(s string) bool {
	if len(s) == 0 {
		return false
	}
	start := 0
	if s[0] == '-' || s[0] == '+' {
		start = 1
	}
	if start >= len(s) {
		return false
	}
	dotSeen := false
	for i := start; i < len(s); i++ {
		if s[i] == '.' {
			if dotSeen {
				return false
			}
			dotSeen = true
		} else if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func assignValue(dest any, src any) error {
	if src == nil {
		return nil
	}

	rv := reflect.ValueOf(dest)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("dest is not a pointer or is nil")
	}

	return assignReflectValue(rv.Elem(), src)
}

func assignReflectValue(target reflect.Value, src any) error {
	if src == nil {
		return nil
	}

	srcVal := reflect.ValueOf(src)

	// Direct assignment if types are compatible
	if srcVal.Type().AssignableTo(target.Type()) {
		target.Set(srcVal)
		return nil
	}

	// Convert via JSON number/string
	switch target.Kind() {
	case reflect.String:
		target.SetString(fmt.Sprintf("%v", src))

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := toInt64(src)
		if err != nil {
			return err
		}
		target.SetInt(n)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := toInt64(src)
		if err != nil {
			return err
		}
		target.SetUint(uint64(n))

	case reflect.Float32, reflect.Float64:
		f, err := toFloat64(src)
		if err != nil {
			return err
		}
		target.SetFloat(f)

	case reflect.Bool:
		b, err := toBool(src)
		if err != nil {
			return err
		}
		target.SetBool(b)

	case reflect.Struct:
		if target.Type() == reflect.TypeOf(time.Time{}) {
			t, err := toTime(src)
			if err != nil {
				return err
			}
			target.Set(reflect.ValueOf(t))
			return nil
		}
		// Try JSON unmarshal for complex structs
		data, err := json.Marshal(src)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, target.Addr().Interface())

	case reflect.Map, reflect.Slice:
		// Try direct assignment first
		if srcVal.Type().AssignableTo(target.Type()) {
			target.Set(srcVal)
			return nil
		}
		// Try JSON round-trip
		data, err := json.Marshal(src)
		if err != nil {
			return err
		}
		newVal := reflect.New(target.Type())
		if err := json.Unmarshal(data, newVal.Interface()); err != nil {
			return err
		}
		target.Set(newVal.Elem())

	default:
		// Last resort: try JSON round-trip
		data, err := json.Marshal(src)
		if err != nil {
			return fmt.Errorf("cannot assign %T to %s", src, target.Type())
		}
		newVal := reflect.New(target.Type())
		if err := json.Unmarshal(data, newVal.Interface()); err != nil {
			return fmt.Errorf("cannot assign %T to %s: %w", src, target.Type(), err)
		}
		target.Set(newVal.Elem())
	}

	return nil
}

func toInt64(v any) (int64, error) {
	switch x := v.(type) {
	case int:
		return int64(x), nil
	case int8:
		return int64(x), nil
	case int16:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return x, nil
	case uint:
		return int64(x), nil
	case uint8:
		return int64(x), nil
	case uint16:
		return int64(x), nil
	case uint32:
		return int64(x), nil
	case uint64:
		return int64(x), nil
	case float32:
		return int64(x), nil
	case float64:
		return int64(x), nil
	case string:
		return strconv.ParseInt(x, 10, 64)
	case json.Number:
		return x.Int64()
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", v)
	}
}

func toFloat64(v any) (float64, error) {
	switch x := v.(type) {
	case float32:
		return float64(x), nil
	case float64:
		return x, nil
	case int:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case string:
		return strconv.ParseFloat(x, 64)
	case json.Number:
		return x.Float64()
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", v)
	}
}

func toBool(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case int, int64, float64:
		return fmt.Sprintf("%v", x) != "0", nil
	case string:
		return x == "1" || strings.EqualFold(x, "true"), nil
	default:
		return false, fmt.Errorf("cannot convert %T to bool", v)
	}
}

func toTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		return x, nil
	case string:
		// Try common formats
		for _, layout := range []string{
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05",
		} {
			if t, err := time.Parse(layout, x); err == nil {
				return t, nil
			}
		}
		// Try as unix timestamp (auto-detect unit)
		if ns, err := strconv.ParseInt(x, 10, 64); err == nil {
			if ns > 1e17 {
				return time.Unix(0, ns), nil
			} else if ns > 1e12 {
				return time.UnixMicro(ns), nil
			} else if ns > 1e9 {
				return time.UnixMilli(ns), nil
			}
			return time.Unix(ns, 0), nil
		}
		return time.Time{}, fmt.Errorf("cannot parse %q as time", x)
	case float64:
		if x > 1e17 {
			return time.Unix(0, int64(x)), nil
		} else if x > 1e12 {
			// OpenObserve _timestamp is in microseconds
			return time.UnixMicro(int64(x)), nil
		} else if x > 1e9 {
			return time.UnixMilli(int64(x)), nil
		}
		return time.Unix(int64(x), 0), nil
	case int64:
		if x > 1e17 {
			return time.Unix(0, x), nil
		} else if x > 1e12 {
			// OpenObserve _timestamp is in microseconds
			return time.UnixMicro(x), nil
		} else if x > 1e9 {
			return time.UnixMilli(x), nil
		}
		return time.Unix(x, 0), nil
	default:
		return time.Time{}, fmt.Errorf("cannot convert %T to time.Time", v)
	}
}

func inferDBType(hits []map[string]any, col string) string {
	for _, hit := range hits {
		if v, ok := hit[col]; ok && v != nil {
			switch v.(type) {
			case string:
				return "String"
			case float64, json.Number:
				return "Float64"
			case bool:
				return "Bool"
			case []any, []string:
				return "Array(String)"
			case map[string]any:
				return "JSON"
			default:
				return "String"
			}
		}
	}
	return "String"
}

func dbTypeToGoType(dbType string) reflect.Type {
	switch dbType {
	case "Float64", "Float32":
		return reflect.TypeOf(float64(0))
	case "Bool":
		return reflect.TypeOf(false)
	case "Array(String)":
		return reflect.TypeOf([]any{})
	case "JSON":
		return reflect.TypeOf(map[string]any{})
	default:
		return reflect.TypeOf("")
	}
}

// floatToTimeStr converts a numeric timestamp to RFC3339Nano string,
// auto-detecting the unit (nanoseconds, microseconds, milliseconds, or seconds)
// based on the magnitude of the value.
func floatToTimeStr(tv float64) string {
	var t time.Time
	if tv > 1e17 {
		// Nanoseconds (e.g. OpenObserve start_time)
		sec := int64(tv / 1e9)
		nsec := int64(tv - float64(sec)*1e9)
		t = time.Unix(sec, nsec).UTC()
	} else if tv > 1e14 {
		// Microseconds (e.g. OpenObserve _timestamp)
		sec := int64(tv / 1e6)
		nsec := int64((tv - float64(sec)*1e6) * 1e3)
		t = time.Unix(sec, nsec).UTC()
	} else if tv > 1e11 {
		// Milliseconds
		t = time.UnixMilli(int64(tv)).UTC()
	} else {
		// Seconds
		t = time.Unix(int64(tv), 0).UTC()
	}
	return t.Format(time.RFC3339Nano)
}
