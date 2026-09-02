package querier

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SigNoz/signoz/pkg/telemetrystore"
	qbtypes "github.com/SigNoz/signoz/pkg/types/querybuildertypes/querybuildertypesv5"
	"github.com/SigNoz/signoz/pkg/types/spantypes"
	"github.com/SigNoz/signoz/pkg/types/telemetrystoretypes"
	"github.com/SigNoz/signoz/pkg/types/telemetrytypes"
)

var (
	aggRe = regexp.MustCompile(`^__result_(\d+)$`)
	// keyAliasRe matches the traces statement builder's positional column-alias prefix
	// `__SELECT_KEY_<n>_` / `__GROUP_BY_KEY_<n>_`, which disambiguates select/group-by
	// aliases from real table columns in the generated SQL. It is stripped here so the
	// original field name surfaces as the label / column / raw-data key.
	// (?i) is needed because OpenObserve lowercases all SQL aliases in response keys.
	keyAliasRe = regexp.MustCompile(`(?i)^__(?:SELECT|GROUP_BY)_KEY_\d+_`)
	// legacyReservedColumnTargetAliases identifies result value from a user
	// written clickhouse query. The column alias indcate which value is
	// to be considered as final result (or target).
	legacyReservedColumnTargetAliases = []string{"__result", "__value", "result", "res", "value"}
)

// stripKeyAlias removes the __SELECT_KEY_<n>_ / __GROUP_BY_KEY_<n>_ prefix from a result
// column name, recovering the field name; unprefixed names are returned unchanged.
func stripKeyAlias(name string) string {
	return keyAliasRe.ReplaceAllString(name, "")
}

// unwrapVariant returns the concrete value inside a Variant envelope.
// With OpenObserve as the store, Dynamic column values arrive as plain types,
// so this is effectively a pass-through.
func unwrapVariant(val any) any {
	return val
}

// labelValue renders a group-by value the payload cannot carry as a scalar — a JSON column, or a
// Dynamic one — as a stable string, so that rows differing only in that value land in different
// series. JSON goes through encoding/json for its sorted map keys: ClickHouse groups documents by
// structure, so two rows it considers equal have to produce the same label.
func labelValue(val any) string {
	val = unwrapVariant(val)
	if val == nil {
		return ""
	}
	if v, ok := val.(telemetrystoretypes.JSONValue); ok {
		if raw, err := json.Marshal(v); err == nil {
			return string(raw)
		}
	}
	return fmt.Sprint(val)
}

// consume reads every row and shapes it into the payload expected for the
// given request type.
//
// * Time-series - *qbtypes.TimeSeriesData
// * Scalar      - *qbtypes.ScalarData
// * Raw         - *qbtypes.RawData
// * Distribution- *qbtypes.DistributionData.
func consume(rows telemetrystore.Rows, kind qbtypes.RequestType, queryWindow *qbtypes.TimeRange, step qbtypes.Step, queryName string) (any, error) {
	var (
		payload any
		err     error
	)

	switch kind {
	case qbtypes.RequestTypeTimeSeries:
		payload, err = readAsTimeSeries(rows, queryWindow, step, queryName)
	case qbtypes.RequestTypeScalar:
		payload, err = readAsScalar(rows, queryName)
	case qbtypes.RequestTypeRaw, qbtypes.RequestTypeTrace, qbtypes.RequestTypeRawStream:
		payload, err = readAsRaw(rows, queryName)
		// TODO: add support for other request types
	}

	return payload, err
}

func readAsTimeSeries(rows telemetrystore.Rows, queryWindow *qbtypes.TimeRange, step qbtypes.Step, queryName string) (*qbtypes.TimeSeriesData, error) {
	colTypes, _ := rows.ColumnTypes()
	colNames, _ := rows.Columns()

	slots := make([]any, len(colTypes))
	numericColsCount := 0
	for i, ct := range colTypes {
		slots[i] = reflect.New(ct.ScanType()).Interface()
		if isNumericKind(ct.ScanType()) {
			numericColsCount++
		}
	}

	type sKey struct {
		agg int
		key string // deterministic join of label values
	}
	seriesMap := map[sKey]*qbtypes.TimeSeries{}

	stepMs := uint64(step.Milliseconds())

	// Helper function to check if a timestamp represents a partial value
	isPartialValue := func(timestamp int64) bool {
		if stepMs == 0 || queryWindow == nil {
			return false
		}

		timestampMs := uint64(timestamp)

		// For the first interval, check if query start is misaligned
		// The first complete interval starts at the first timestamp >= queryWindow.From that is aligned to step
		firstCompleteInterval := queryWindow.From
		if queryWindow.From%stepMs != 0 {
			// Round up to next step boundary
			firstCompleteInterval = ((queryWindow.From / stepMs) + 1) * stepMs
		}

		// If timestamp is before the first complete interval, it's partial
		if timestampMs < firstCompleteInterval {
			return true
		}

		// For the last interval, check if it would extend beyond query end
		if timestampMs+stepMs > queryWindow.To {
			return queryWindow.To%stepMs != 0
		}

		return false
	}

	// Pre-allocate for labels based on column count
	lblValsCapacity := len(colNames) - 1 // -1 for timestamp
	if lblValsCapacity < 0 {
		lblValsCapacity = 0
	}

	for rows.Next() {
		if err := rows.Scan(slots...); err != nil {
			return nil, err
		}

		var (
			ts            int64
			lblVals       = make([]string, 0, lblValsCapacity)
			lblObjs       = make([]*qbtypes.Label, 0, lblValsCapacity)
			aggValues     = map[int]float64{} // all __result_N in this row
			fallbackValue float64             // value when NO __result_N columns exist
			fallbackSeen  bool
		)

		for idx, ptr := range slots {
			name := stripKeyAlias(colNames[idx])

			switch v := ptr.(type) {
			case *time.Time:
				ts = v.UnixMilli()

			case *float64, *float32, *int64, *int32, *uint64, *uint32:
				val := numericAsFloat(reflect.ValueOf(ptr).Elem().Interface())
				if m := aggRe.FindStringSubmatch(name); m != nil {
					id, _ := strconv.Atoi(m[1])
					aggValues[id] = val
				} else if numericColsCount == 1 { // classic single-value query
					fallbackValue = val
					fallbackSeen = true
				} else if slices.Contains(legacyReservedColumnTargetAliases, name) {
					fallbackValue = val
					fallbackSeen = true
				} else {
					// numeric label
					lblVals = append(lblVals, fmt.Sprint(val))
					lblObjs = append(lblObjs, &qbtypes.Label{
						Key:   telemetrytypes.TelemetryFieldKey{Name: name},
						Value: val,
					})
				}

			case **float64, **float32, **int64, **int32, **uint64, **uint32:
				tempVal := reflect.ValueOf(ptr)
				if tempVal.IsValid() && !tempVal.IsNil() && !tempVal.Elem().IsNil() {
					val := numericAsFloat(tempVal.Elem().Elem().Interface())
					if m := aggRe.FindStringSubmatch(name); m != nil {
						id, _ := strconv.Atoi(m[1])
						aggValues[id] = val
					} else if numericColsCount == 1 { // classic single-value query
						fallbackValue = val
						fallbackSeen = true
					} else if slices.Contains(legacyReservedColumnTargetAliases, name) {
						fallbackValue = val
						fallbackSeen = true
					} else {
						// numeric label
						lblVals = append(lblVals, fmt.Sprint(val))
						lblObjs = append(lblObjs, &qbtypes.Label{
							Key:   telemetrytypes.TelemetryFieldKey{Name: name},
							Value: val,
						})
					}
				}

			case *string:
				lblVals = append(lblVals, *v)
				lblObjs = append(lblObjs, &qbtypes.Label{
					Key:   telemetrytypes.TelemetryFieldKey{Name: name},
					Value: *v,
				})

			case **string:
				val := *v
				if val == nil {
					var empty string
					val = &empty
				}
				lblVals = append(lblVals, *val)
				lblObjs = append(lblObjs, &qbtypes.Label{
					Key:   telemetrytypes.TelemetryFieldKey{Name: name},
					Value: *val,
				})

			case *telemetrystoretypes.JSONValue:
				val := labelValue(derefValue(ptr))
				lblVals = append(lblVals, val)
				lblObjs = append(lblObjs, &qbtypes.Label{
					Key:   telemetrytypes.TelemetryFieldKey{Name: name},
					Value: val,
				})

			default:
				continue
			}
		}

		// Edge-case: no __result_N columns, but a single numeric column present
		if len(aggValues) == 0 && fallbackSeen {
			aggValues[0] = fallbackValue
		}

		if ts == 0 || len(aggValues) == 0 {
			continue // nothing useful
		}

		sort.Strings(lblVals)
		labelsKey := strings.Join(lblVals, ",")

		// one point per aggregation in this row
		for aggIdx, val := range aggValues {
			if math.IsNaN(val) || math.IsInf(val, 0) {
				continue
			}

			key := sKey{agg: aggIdx, key: labelsKey}

			series, ok := seriesMap[key]
			if !ok {
				series = &qbtypes.TimeSeries{Labels: lblObjs}
				seriesMap[key] = series
			}
			series.Values = append(series.Values, &qbtypes.TimeSeriesValue{
				Timestamp: ts,
				Value:     val,
				Partial:   isPartialValue(ts),
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	maxAgg := -1
	for k := range seriesMap {
		if k.agg > maxAgg {
			maxAgg = k.agg
		}
	}
	if maxAgg < 0 {
		return &qbtypes.TimeSeriesData{
			QueryName: queryName,
		}, nil
	}

	buckets := make([]*qbtypes.AggregationBucket, maxAgg+1)
	for i := range buckets {
		buckets[i] = &qbtypes.AggregationBucket{
			Index: i,
			Alias: "__result_" + strconv.Itoa(i),
		}
	}
	for k, s := range seriesMap {
		buckets[k.agg].Series = append(buckets[k.agg].Series, s)
	}

	var nonEmpty []*qbtypes.AggregationBucket
	for _, b := range buckets {
		if len(b.Series) > 0 {
			nonEmpty = append(nonEmpty, b)
		}
	}

	return &qbtypes.TimeSeriesData{
		QueryName:    queryName,
		Aggregations: nonEmpty,
	}, nil
}

func isNumericKind(t reflect.Type) bool {
	if t == nil {
		return false
	}
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.UnsafePointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Float32, reflect.Float64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

func readAsScalar(rows telemetrystore.Rows, queryName string) (*qbtypes.ScalarData, error) {
	colNames, _ := rows.Columns()
	colTypes, _ := rows.ColumnTypes()

	cd := make([]*qbtypes.ColumnDescriptor, len(colNames))

	var aggIndex int64
	for i, name := range colNames {
		name = stripKeyAlias(name)
		colType := qbtypes.ColumnTypeGroup
		// Builder queries aliases aggregation columns as __result_N (always numeric) and wraps group-by keys with toString (always string);
		// Raw ClickHouse queries may use any aliases.
		// Handling Builder queries, If name like __result_N -> aggregation, otherwise group-by column
		// Handling Raw ClickHouse queries, If type is numeric -> aggregation, otherwise group-by column
		// NOTE: For clickhouse queries, its wrong to assume that numeric columns are always aggregations, user might be grouping by on integer status_code.
		// However, we are fine with this for now. If need arises, simplest way would be to solve this on the frontend side by asking user a mapping of column names to column types.
		if aggRe.MatchString(name) || isNumericKind(colTypes[i].ScanType()) {
			colType = qbtypes.ColumnTypeAggregation
		}
		cd[i] = &qbtypes.ColumnDescriptor{
			TelemetryFieldKey: telemetrytypes.TelemetryFieldKey{Name: name},
			QueryName:         queryName,
			AggregationIndex:  aggIndex,
			Type:              colType,
		}
		if colType == qbtypes.ColumnTypeAggregation {
			aggIndex++
		}
	}

	// Pre-allocate scan slots once
	scan := make([]any, len(colTypes))
	for i := range scan {
		scan[i] = reflect.New(colTypes[i].ScanType()).Interface()
	}

	var data [][]any

	for rows.Next() {
		if err := rows.Scan(scan...); err != nil {
			return nil, err
		}

		// 2. deref each slot into the output row
		row := make([]any, len(scan))
		for i, cell := range scan {
			row[i] = unwrapVariant(derefValue(cell))
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &qbtypes.ScalarData{
		QueryName: queryName,
		Columns:   cd,
		Data:      data,
	}, nil
}

func derefValue(v any) any {
	if v == nil {
		return nil
	}

	val := reflect.ValueOf(v)

	for val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return nil
		}
		val = val.Elem()
	}

	return val.Interface()
}

func readAsRaw(rows telemetrystore.Rows, queryName string) (*qbtypes.RawData, error) {
	colNames, _ := rows.Columns()
	colTypes, _ := rows.ColumnTypes()
	colCnt := len(colNames)

	var outRows []*qbtypes.RawRow

	for rows.Next() {
		// fresh copy of the scan slice (otherwise the driver reuses pointers)
		scan := make([]any, colCnt)
		for i := range colTypes {
			scan[i] = reflect.New(colTypes[i].ScanType()).Interface()
		}

		if err := rows.Scan(scan...); err != nil {
			return nil, err
		}

		rr := qbtypes.RawRow{
			Data: make(map[string]any, colCnt),
		}

		for i, cellPtr := range scan {
			name := stripKeyAlias(colNames[i])

			// de-reference the typed pointer to any
			val := unwrapVariant(reflect.ValueOf(cellPtr).Elem().Interface())

			// special-case: timestamp column
			// OpenObserve uses _timestamp (microseconds); SigNoz frontend expects timestamp (nanoseconds).
			if name == "timestamp" || name == "timestamp_datetime" || name == "_timestamp" {
				rr.Timestamp = toTimestamp(val)
			}

			// OpenObserve stores _timestamp in microseconds; the frontend expects
			// a "timestamp" key in nanoseconds.  Rename and convert here so that
			// the response is compatible with the SigNoz frontend contract.
			if name == "_timestamp" {
				rr.Data["timestamp"] = toEpochNano(val)
			}

			rr.Data[name] = val
		}
		outRows = append(outRows, &rr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &qbtypes.RawData{
		QueryName: queryName,
		Rows:      outRows,
	}, nil
}

// mergeSpanAttributeColumns merges (attributes_string, attributes_number, attributes_bool, resources_string) into
// unified "attributes" and "resource" keys, and parses the stringified `events`
// and `links` columns into structured slices. Raw DB columns are removed.
func mergeSpanAttributeColumns(data map[string]any) {
	attrStr, hasStr := data["attributes_string"]
	attrNum, hasNum := data["attributes_number"]
	attrBool, hasBool := data["attributes_bool"]
	// todo(nitya): move to resource json
	resStr, hasRes := data["resources_string"]
	if hasStr || hasNum || hasBool || hasRes {
		attributes := make(map[string]any)
		if m, ok := attrStr.(map[string]string); ok {
			for k, v := range m {
				attributes[k] = v
			}
		}
		if m, ok := attrNum.(map[string]float64); ok {
			for k, v := range m {
				attributes[k] = v
			}
		}
		if m, ok := attrBool.(map[string]bool); ok {
			for k, v := range m {
				attributes[k] = v
			}
		}
		delete(data, "attributes_string")
		delete(data, "attributes_number")
		delete(data, "attributes_bool")
		data["attributes"] = attributes

		resource := map[string]string{}
		if m, ok := resStr.(map[string]string); ok {
			resource = m
		}
		data["resource"] = resource
		delete(data, "resources_string")
	}

	if raw, ok := data["events"]; ok {
		data["events"] = spantypes.ParseEvents(raw)
	}
	if raw, ok := data["links"]; ok {
		data["links"] = spantypes.ParseLinks(raw)
	}
}

// numericAsFloat converts numeric types to float64 efficiently.
func numericAsFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case float32:
		return float64(x)
	case int32:
		return float64(x)
	case uint64:
		return float64(x)
	case uint32:
		return float64(x)
	case int:
		return float64(x)
	case uint:
		return float64(x)
	case int16:
		return float64(x)
	case int8:
		return float64(x)
	case uint16:
		return float64(x)
	case uint8:
		return float64(x)
	default:
		return math.NaN()
	}
}

// toEpochMicro converts any value to epoch microseconds.
// OpenObserve _timestamp is in microseconds; this function handles all types
// that OpenObserve may return (float64, int64, string, etc.).
func toEpochMicro(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case uint64:
		return int64(x)
	case int:
		return int64(x)
	case string:
		if f, err := strconv.ParseFloat(x, 64); err == nil {
			return int64(f)
		}
	case json.Number:
		if f, err := x.Float64(); err == nil {
			return int64(f)
		}
	}
	return 0
}

// toTimestamp converts any value to time.Time.
// It auto-detects the epoch unit (nanoseconds, microseconds, milliseconds, seconds).
func toTimestamp(v any) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x
	case string:
		// Try RFC3339 first
		if t, err := time.Parse(time.RFC3339Nano, x); err == nil {
			return t
		}
		// Try as numeric epoch
		if f, err := strconv.ParseFloat(x, 64); err == nil {
			return epochToTime(int64(f))
		}
		return time.Time{}
	default:
		return epochToTime(toEpochMicro(v))
	}
}

// epochToTime converts an epoch value to time.Time, auto-detecting the unit.
// Thresholds are chosen to avoid ambiguity for dates between year 2000 and 2250:
//   - microseconds: ~9.5e14 (2000) to ~8.9e15 (2250)  → always < 1e16
//   - nanoseconds:  ~9.5e17 (2000) to ~8.9e18 (2250)  → always > 1e17
func epochToTime(iv int64) time.Time {
	if iv > 1e17 { // nanoseconds
		return time.Unix(0, iv)
	} else if iv > 1e12 { // microseconds
		return time.UnixMicro(iv)
	} else if iv > 1e9 { // milliseconds
		return time.UnixMilli(iv)
	} else if iv > 0 { // seconds
		return time.Unix(iv, 0)
	}
	return time.Time{}
}

// toEpochNano converts any value to epoch nanoseconds (int64).
// OpenObserve _timestamp is in microseconds, so we multiply by 1000.
func toEpochNano(v any) int64 {
	micro := toEpochMicro(v)
	if micro == 0 {
		return 0
	}
	// If the value is already in nanoseconds range (>1e17), return as-is
	if micro > 1e17 {
		return micro
	}
	// Otherwise treat as microseconds and convert to nanoseconds
	return micro * 1000
}
