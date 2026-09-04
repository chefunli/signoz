package implservices

import (
	"context"
	"fmt"
	"strings"
	"time"

	"strconv"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/modules/services"
	"github.com/SigNoz/signoz/pkg/querier"
	"github.com/SigNoz/signoz/pkg/telemetryschema/tracestelemetryschema"
	"github.com/SigNoz/signoz/pkg/telemetrystore"
	"github.com/SigNoz/signoz/pkg/types/ctxtypes"
	"github.com/SigNoz/signoz/pkg/types/instrumentationtypes"
	qbtypes "github.com/SigNoz/signoz/pkg/types/querybuildertypes/querybuildertypesv5"
	"github.com/SigNoz/signoz/pkg/types/servicetypes/servicetypesv1"
	"github.com/SigNoz/signoz/pkg/types/telemetrytypes"
	"github.com/SigNoz/signoz/pkg/valuer"
)

type module struct {
	Querier        querier.Querier
	TelemetryStore telemetrystore.TelemetryStore
	Provider       string // "clickhouse" or "openobserve"
}

// NewModule constructs the services module with the provided querier dependency.
func NewModule(q querier.Querier, ts telemetrystore.TelemetryStore, provider string) services.Module {
	return &module{
		Querier:        q,
		TelemetryStore: ts,
		Provider:       provider,
	}
}

// FetchTopLevelOperations returns top-level operations per service using db query.
func (m *module) FetchTopLevelOperations(ctx context.Context, start time.Time, services []string) (map[string][]string, error) {
	ctx = m.withServicesContext(ctx, "FetchTopLevelOperations")

	// OpenObserve: query traces directly for root span operations
	if m.Provider == "openobserve" {
		return m.fetchTopLevelOpsOpenObserve(ctx, start, services)
	}

	// ClickHouse: use the pre-computed top_level_operations table
	db := m.TelemetryStore.DB()
	query := fmt.Sprintf("SELECT name, serviceName, max(time) as ts FROM %s.%s WHERE time >= @start", tracestelemetryschema.DBName, tracestelemetryschema.TopLevelOperationsTableName)
	args := []any{clickhouse.Named("start", start)}
	if len(services) > 0 {
		query += " AND serviceName IN @services"
		args = append(args, clickhouse.Named("services", services))
	}
	query += " GROUP BY name, serviceName ORDER BY ts DESC LIMIT 5000"

	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, errors.WrapInternalf(err, errors.CodeInternal, "failed to fetch top level operations")
	}
	defer rows.Close()

	ops := make(map[string][]string)
	if err := rows.Err(); err != nil {
		return nil, errors.WrapInternalf(err, errors.CodeInternal, "failed to fetch top level operations")
	}
	for rows.Next() {
		var name, serviceName string
		var ts time.Time
		if err := rows.Scan(&name, &serviceName, &ts); err != nil {
			return nil, errors.WrapInternalf(err, errors.CodeInternal, "failed to scan top level operation")
		}
		if _, ok := ops[serviceName]; !ok {
			ops[serviceName] = []string{"overflow_operation"}
		}
		ops[serviceName] = append(ops[serviceName], name)
	}
	return ops, nil
}

// fetchTopLevelOpsOpenObserve queries OpenObserve traces for root span operations per service.
func (m *module) fetchTopLevelOpsOpenObserve(ctx context.Context, start time.Time, services []string) (map[string][]string, error) {
	startMicro := uint64(start.UnixMicro())
	nowMicro := uint64(time.Now().UnixMicro())

	sql := fmt.Sprintf(
		`SELECT service_name, operation_name FROM "default" `+
			`WHERE _timestamp >= %d AND _timestamp <= %d `+
			`AND (reference_parent_span_id IS NULL OR reference_parent_span_id = '') `+
			`GROUP BY service_name, operation_name ORDER BY service_name`,
		startMicro, nowMicro,
	)

	if len(services) > 0 {
		quoted := make([]string, len(services))
		for i, s := range services {
			quoted[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(s, "'", "''"))
		}
		sql = fmt.Sprintf(
			`SELECT service_name, operation_name FROM "default" `+
				`WHERE _timestamp >= %d AND _timestamp <= %d `+
				`AND (reference_parent_span_id IS NULL OR reference_parent_span_id = '') `+
				`AND service_name IN (%s) `+
				`GROUP BY service_name, operation_name ORDER BY service_name`,
			startMicro, nowMicro, strings.Join(quoted, ","),
		)
	}

	db := m.TelemetryStore.DB()
	rows, err := db.Query(ctx, sql)
	if err != nil {
		return nil, errors.WrapInternalf(err, errors.CodeInternal, "failed to fetch top level operations from openobserve")
	}
	defer rows.Close()

	ops := make(map[string][]string)
	for rows.Next() {
		var serviceName, opName string
		if err := rows.Scan(&serviceName, &opName); err != nil {
			return nil, errors.WrapInternalf(err, errors.CodeInternal, "failed to scan top level operation")
		}
		if _, ok := ops[serviceName]; !ok {
			ops[serviceName] = []string{"overflow_operation"}
		}
		ops[serviceName] = append(ops[serviceName], opName)
	}
	return ops, nil
}

// Get implements services.Module
func (m *module) Get(ctx context.Context, orgUUID valuer.UUID, req *servicetypesv1.Request) ([]*servicetypesv1.ResponseItem, error) {
	ctx = m.withServicesContext(ctx, "Get")
	if req == nil {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "request is nil")
	}

	// OpenObserve uses a direct SQL path for performance (bypasses QBv5 pipeline)
	if m.Provider == "openobserve" {
		return m.getOpenObserve(ctx, req)
	}

	// ClickHouse (and other providers) use the standard QBv5 pipeline
	return m.getQBv5(ctx, orgUUID, req)
}

// parseTimeToMicro parses a time string (milliseconds or nanoseconds) and returns microseconds.
// Auto-detects the unit based on magnitude to avoid uint64 overflow.
func parseTimeToMicro(s string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	// Nanoseconds (>1e15): convert to microseconds
	if v > 1e15 {
		return v / 1000, nil
	}
	// Milliseconds (<=1e15): convert to microseconds
	return v * 1000, nil
}

// parseTimeToMilli parses a time string (milliseconds or nanoseconds) and returns milliseconds.
func parseTimeToMilli(s string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	// Nanoseconds (>1e15): convert to milliseconds
	if v > 1e15 {
		return v / 1_000_000, nil
	}
	// Already milliseconds
	return v, nil
}

// getOpenObserve executes the services query directly against OpenObserve for performance.
func (m *module) getOpenObserve(ctx context.Context, req *servicetypesv1.Request) ([]*servicetypesv1.ResponseItem, error) {
	startMicro, err := parseTimeToMicro(req.Start)
	if err != nil {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "invalid start time: %v", err)
	}
	endMicro, err := parseTimeToMicro(req.End)
	if err != nil {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "invalid end time: %v", err)
	}
	if startMicro >= endMicro {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "start must be before end")
	}

	items, serviceNames, err := m.getDirect(ctx, startMicro, endMicro)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return []*servicetypesv1.ResponseItem{}, nil
	}

	if len(serviceNames) > 0 {
		// attachTopLevelOps expects milliseconds
		startMs := startMicro / 1000
		if err := m.attachTopLevelOps(ctx, serviceNames, startMs, items); err != nil {
			return nil, err
		}
	}
	return items, nil
}

// getQBv5 executes the services query through the standard QBv5 pipeline (for ClickHouse).
func (m *module) getQBv5(ctx context.Context, orgUUID valuer.UUID, req *servicetypesv1.Request) ([]*servicetypesv1.ResponseItem, error) {
	queryRangeReq, startMs, endMs, err := m.buildQueryRangeRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := m.executeQuery(ctx, orgUUID, queryRangeReq)
	if err != nil {
		return nil, err
	}

	items, serviceNames := m.mapQueryRangeRespToServices(resp, startMs, endMs)
	if len(items) == 0 {
		return []*servicetypesv1.ResponseItem{}, nil
	}

	if len(serviceNames) > 0 {
		if err := m.attachTopLevelOps(ctx, serviceNames, startMs, items); err != nil {
			return nil, err
		}
	}
	return items, nil
}

// getDirect executes the services aggregation query directly against the telemetry store.
// This bypasses the QBv5 pipeline for much better performance (0.3s vs 20+ seconds).
func (m *module) getDirect(ctx context.Context, startMicro, endMicro uint64) ([]*servicetypesv1.ResponseItem, []string, error) {
	sql := fmt.Sprintf(
		`SELECT service_name, PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY duration) as p99, `+
			`AVG(duration) as avg_duration, COUNT(*) as num_calls, `+
			`COUNT(CASE WHEN status_code = 2 THEN 1 END) as num_errors, `+
			`COUNT(CASE WHEN http_response_status_code >= 400 AND http_response_status_code < 500 THEN 1 END) as num_4xx `+
			`FROM "default" `+
			`WHERE _timestamp >= %d AND _timestamp <= %d `+
			`GROUP BY service_name ORDER BY num_calls DESC`,
		startMicro, endMicro,
	)

	db := m.TelemetryStore.DB()
	rows, err := db.Query(ctx, sql)
	if err != nil {
		return nil, nil, errors.WrapInternalf(err, errors.CodeInternal, "services direct query failed")
	}
	defer rows.Close()

	periodSeconds := float64(endMicro-startMicro) / 1_000_000.0

	var items []*servicetypesv1.ResponseItem
	var serviceNames []string
	for rows.Next() {
		var serviceName string
		var p99, avgDuration float64
		var numCalls, numErrors, num4xx uint64
		if err := rows.Scan(&serviceName, &p99, &avgDuration, &numCalls, &numErrors, &num4xx); err != nil {
			return nil, nil, errors.WrapInternalf(err, errors.CodeInternal, "failed to scan service row")
		}

		callRate := 0.0
		if numCalls > 0 {
			callRate = float64(numCalls) / periodSeconds
		}
		errorRate := 0.0
		if numCalls > 0 {
			errorRate = float64(numErrors) * 100 / float64(numCalls)
		}
		fourXXRate := 0.0
		if numCalls > 0 {
			fourXXRate = float64(num4xx) * 100 / float64(numCalls)
		}

		items = append(items, &servicetypesv1.ResponseItem{
			ServiceName:  serviceName,
			Percentile99: p99,
			AvgDuration:  avgDuration,
			NumCalls:     numCalls,
			CallRate:     callRate,
			NumErrors:    numErrors,
			ErrorRate:    errorRate,
			Num4XX:       num4xx,
			FourXXRate:   fourXXRate,
			DataWarning:  servicetypesv1.DataWarning{TopLevelOps: []string{}},
		})
		serviceNames = append(serviceNames, serviceName)
	}
	return items, serviceNames, nil
}

// GetTopOperations implements services.Module for QBV5 based top ops.
func (m *module) GetTopOperations(ctx context.Context, orgUUID valuer.UUID, req *servicetypesv1.OperationsRequest) ([]servicetypesv1.OperationItem, error) {
	ctx = m.withServicesContext(ctx, "GetTopOperations")
	if req == nil {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "request is nil")
	}

	qr, err := m.buildTopOpsQueryRangeRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := m.executeQuery(ctx, orgUUID, qr)
	if err != nil {
		return nil, err
	}

	items := m.mapTopOpsQueryRangeResp(resp)
	return items, nil
}

// GetEntryPointOperations implements services.Module for QBV5 based entry point ops.
func (m *module) GetEntryPointOperations(ctx context.Context, orgUUID valuer.UUID, req *servicetypesv1.OperationsRequest) ([]servicetypesv1.OperationItem, error) {
	ctx = m.withServicesContext(ctx, "GetEntryPointOperations")
	if req == nil {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "request is nil")
	}

	qr, err := m.buildEntryPointOpsQueryRangeRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := m.executeQuery(ctx, orgUUID, qr)
	if err != nil {
		return nil, err
	}

	items := m.mapEntryPointOpsQueryRangeResp(resp)
	return items, nil
}

// buildQueryRangeRequest constructs the QBv5 QueryRangeRequest and computes the time window.
func (m *module) buildQueryRangeRequest(req *servicetypesv1.Request) (*qbtypes.QueryRangeRequest, uint64, uint64, error) {
	startMs, err := parseTimeToMilli(req.Start)
	if err != nil {
		return nil, 0, 0, errors.NewInvalidInputf(errors.CodeInvalidInput, "invalid start time: %v", err)
	}
	endMs, err := parseTimeToMilli(req.End)
	if err != nil {
		return nil, 0, 0, errors.NewInvalidInputf(errors.CodeInvalidInput, "invalid end time: %v", err)
	}
	if startMs >= endMs {
		return nil, 0, 0, errors.NewInvalidInputf(errors.CodeInvalidInput, "start must be before end")
	}
	if err := validateTagFilterItems(req.Tags); err != nil {
		return nil, 0, 0, err
	}

	// tags filter
	filterExpr, variables := buildFilterExpression(req.Tags)

	reqV5 := qbtypes.QueryRangeRequest{
		Start:       startMs,
		End:         endMs,
		RequestType: qbtypes.RequestTypeScalar,
		Variables:   variables,
		CompositeQuery: qbtypes.CompositeQuery{
			Queries: []qbtypes.QueryEnvelope{
				{Type: qbtypes.QueryTypeBuilder,
					Spec: qbtypes.QueryBuilderQuery[qbtypes.TraceAggregation]{
						Name:   "A",
						Signal: telemetrytypes.SignalTraces,
						Filter: &qbtypes.Filter{
							Expression: filterExpr,
						},
						GroupBy: []qbtypes.GroupByKey{
							{TelemetryFieldKey: telemetrytypes.TelemetryFieldKey{
								Name:          "service.name",
								FieldContext:  telemetrytypes.FieldContextResource,
								FieldDataType: telemetrytypes.FieldDataTypeString,
								Materialized:  true,
							}},
						},
						Aggregations: []qbtypes.TraceAggregation{
							{Expression: "p99(duration_nano)", Alias: "p99"},
							{Expression: "avg(duration_nano)", Alias: "avgDuration"},
							{Expression: "count()", Alias: "numCalls"},
							{Expression: "countIf(status_code = 2)", Alias: "numErrors"},
							{Expression: "countIf(response_status_code >= 400 AND response_status_code < 500)", Alias: "num4XX"},
						},
					},
				},
			},
		},
	}

	return &reqV5, startMs, endMs, nil
}

// executeQuery calls the underlying Querier with the provided request.
func (m *module) executeQuery(ctx context.Context, orgUUID valuer.UUID, qr *qbtypes.QueryRangeRequest) (*qbtypes.QueryRangeResponse, error) {
	return m.Querier.QueryRange(ctx, orgUUID, qr)
}

// mapQueryRangeRespToServices converts the raw query response into service items and collected service names.
func (m *module) mapQueryRangeRespToServices(resp *qbtypes.QueryRangeResponse, startMs, endMs uint64) ([]*servicetypesv1.ResponseItem, []string) {
	if resp == nil || len(resp.Data.Results) == 0 { // no rows
		return []*servicetypesv1.ResponseItem{}, []string{}
	}

	sd, ok := resp.Data.Results[0].(*qbtypes.ScalarData) // empty rows
	if !ok || sd == nil {
		return []*servicetypesv1.ResponseItem{}, []string{}
	}

	// this stores the index at which service name is found in the response
	serviceNameRespIndex := -1
	aggIndexMappings := map[int]int{}
	for i, c := range sd.Columns {
		switch c.Type {
		case qbtypes.ColumnTypeGroup:
			// Match both "service.name" (ClickHouse) and "service_name" (OpenObserve
			// replaces dots with underscores in column aliases)
			if c.Name == "service.name" || c.Name == "service_name" {
				serviceNameRespIndex = i
			}
		case qbtypes.ColumnTypeAggregation:
			aggIndexMappings[int(c.AggregationIndex)] = i
		}
	}

	periodSeconds := float64((endMs - startMs) / 1000)

	out := make([]*servicetypesv1.ResponseItem, 0, len(sd.Data))
	serviceNames := make([]string, 0, len(sd.Data))
	for _, row := range sd.Data {
		svcName := fmt.Sprintf("%v", row[serviceNameRespIndex])
		serviceNames = append(serviceNames, svcName)

		p99 := toFloat(row, aggIndexMappings[0])
		avgDuration := toFloat(row, aggIndexMappings[1])
		numCalls := toUint64(row, aggIndexMappings[2])
		numErrors := toUint64(row, aggIndexMappings[3])
		num4xx := toUint64(row, aggIndexMappings[4])

		callRate := 0.0
		if numCalls > 0 {
			callRate = float64(numCalls) / periodSeconds
		}
		errorRate := 0.0
		if numCalls > 0 {
			errorRate = float64(numErrors) * 100 / float64(numCalls) // percentage
		}
		fourXXRate := 0.0
		if numCalls > 0 {
			fourXXRate = float64(num4xx) * 100 / float64(numCalls) // percentage
		}

		out = append(out, &servicetypesv1.ResponseItem{
			ServiceName:  svcName,
			Percentile99: p99,
			AvgDuration:  avgDuration,
			NumCalls:     numCalls,
			CallRate:     callRate,
			NumErrors:    numErrors,
			ErrorRate:    errorRate,
			Num4XX:       num4xx,
			FourXXRate:   fourXXRate,
			DataWarning:  servicetypesv1.DataWarning{TopLevelOps: []string{}},
		})
	}

	return out, serviceNames
}

// attachTopLevelOps fetches top-level ops from TelemetryStore and attaches them to items.
func (m *module) attachTopLevelOps(ctx context.Context, serviceNames []string, startMs uint64, items []*servicetypesv1.ResponseItem) error {
	startTime := time.UnixMilli(int64(startMs)).UTC()
	opsMap, err := m.FetchTopLevelOperations(ctx, startTime, serviceNames)
	if err != nil {
		// Don't fail the entire request if top level operations can't be fetched
		// Just log and continue — services will show without topLevelOps
		return nil
	}
	applyOpsToItems(items, opsMap)
	return nil
}

func (m *module) buildTopOpsQueryRangeRequest(req *servicetypesv1.OperationsRequest) (*qbtypes.QueryRangeRequest, error) {
	if req.Service == "" {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "service is required")
	}
	startMs, err := parseTimeToMilli(req.Start)
	if err != nil {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "invalid start time: %v", err)
	}
	endMs, err := parseTimeToMilli(req.End)
	if err != nil {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "invalid end time: %v", err)
	}
	if startMs >= endMs {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "start must be before end")
	}
	if req.Limit < 1 || req.Limit > 5000 {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "limit must be between 1 and 5000")
	}
	if err := validateTagFilterItems(req.Tags); err != nil {
		return nil, err
	}

	serviceTag := servicetypesv1.TagFilterItem{
		Key:          "service.name",
		Operator:     "in",
		StringValues: []string{req.Service},
	}
	tags := append([]servicetypesv1.TagFilterItem{serviceTag}, req.Tags...)
	filterExpr, variables := buildFilterExpression(tags)

	reqV5 := qbtypes.QueryRangeRequest{
		Start:       startMs,
		End:         endMs,
		RequestType: qbtypes.RequestTypeScalar,
		Variables:   variables,
		CompositeQuery: qbtypes.CompositeQuery{
			Queries: []qbtypes.QueryEnvelope{
				{Type: qbtypes.QueryTypeBuilder,
					Spec: qbtypes.QueryBuilderQuery[qbtypes.TraceAggregation]{
						Name:   "A",
						Signal: telemetrytypes.SignalTraces,
						Filter: &qbtypes.Filter{Expression: filterExpr},
						GroupBy: []qbtypes.GroupByKey{
							{TelemetryFieldKey: telemetrytypes.TelemetryFieldKey{
								Name:          "name",
								FieldContext:  telemetrytypes.FieldContextSpan,
								FieldDataType: telemetrytypes.FieldDataTypeString,
							}},
						},
						Aggregations: []qbtypes.TraceAggregation{
							{Expression: "p50(duration_nano)", Alias: "p50"},
							{Expression: "p95(duration_nano)", Alias: "p95"},
							{Expression: "p99(duration_nano)", Alias: "p99"},
							{Expression: "count()", Alias: "numCalls"},
							{Expression: "countIf(status_code = 2)", Alias: "errorCount"},
						},
						Order: []qbtypes.OrderBy{
							{Key: qbtypes.OrderByKey{TelemetryFieldKey: telemetrytypes.TelemetryFieldKey{Name: "p99"}}, Direction: qbtypes.OrderDirectionDesc},
						},
						Limit: req.Limit,
					},
				},
			},
		},
	}
	return &reqV5, nil
}

func (m *module) mapTopOpsQueryRangeResp(resp *qbtypes.QueryRangeResponse) []servicetypesv1.OperationItem {
	if resp == nil || len(resp.Data.Results) == 0 {
		return []servicetypesv1.OperationItem{}
	}
	sd, ok := resp.Data.Results[0].(*qbtypes.ScalarData)
	if !ok || sd == nil {
		return []servicetypesv1.OperationItem{}
	}

	nameIdx := -1
	aggIdx := map[int]int{}
	for i, c := range sd.Columns {
		switch c.Type {
		case qbtypes.ColumnTypeGroup:
			if c.Name == "name" {
				nameIdx = i
			}
		case qbtypes.ColumnTypeAggregation:
			aggIdx[int(c.AggregationIndex)] = i
		}
	}

	out := make([]servicetypesv1.OperationItem, 0, len(sd.Data))
	for _, row := range sd.Data {
		item := servicetypesv1.OperationItem{
			Name:       fmt.Sprintf("%v", row[nameIdx]),
			P50:        toFloat(row, aggIdx[0]),
			P95:        toFloat(row, aggIdx[1]),
			P99:        toFloat(row, aggIdx[2]),
			NumCalls:   toUint64(row, aggIdx[3]),
			ErrorCount: toUint64(row, aggIdx[4]),
		}
		out = append(out, item)
	}
	return out
}

func (m *module) buildEntryPointOpsQueryRangeRequest(req *servicetypesv1.OperationsRequest) (*qbtypes.QueryRangeRequest, error) {
	if req.Service == "" {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "service is required")
	}
	startMs, err := parseTimeToMilli(req.Start)
	if err != nil {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "invalid start time: %v", err)
	}
	endMs, err := parseTimeToMilli(req.End)
	if err != nil {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "invalid end time: %v", err)
	}
	if startMs >= endMs {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "start must be before end")
	}
	if req.Limit < 1 || req.Limit > 5000 {
		return nil, errors.NewInvalidInputf(errors.CodeInvalidInput, "limit must be between 1 and 5000")
	}
	if err := validateTagFilterItems(req.Tags); err != nil {
		return nil, err
	}

	serviceTag := servicetypesv1.TagFilterItem{
		Key:          "service.name",
		Operator:     "in",
		StringValues: []string{req.Service},
	}
	tags := append([]servicetypesv1.TagFilterItem{serviceTag}, req.Tags...)
	filterExpr, variables := buildFilterExpression(tags)
	scopeExpr := "isRoot = true OR isEntryPoint = true"
	if filterExpr != "" {
		filterExpr = "(" + filterExpr + ") AND (" + scopeExpr + ")"
	} else {
		filterExpr = scopeExpr
	}

	reqV5 := qbtypes.QueryRangeRequest{
		Start:       startMs,
		End:         endMs,
		RequestType: qbtypes.RequestTypeScalar,
		Variables:   variables,
		CompositeQuery: qbtypes.CompositeQuery{
			Queries: []qbtypes.QueryEnvelope{
				{Type: qbtypes.QueryTypeBuilder,
					Spec: qbtypes.QueryBuilderQuery[qbtypes.TraceAggregation]{
						Name:   "A",
						Signal: telemetrytypes.SignalTraces,
						Filter: &qbtypes.Filter{Expression: filterExpr},
						GroupBy: []qbtypes.GroupByKey{
							{TelemetryFieldKey: telemetrytypes.TelemetryFieldKey{
								Name:          "name",
								FieldContext:  telemetrytypes.FieldContextSpan,
								FieldDataType: telemetrytypes.FieldDataTypeString,
							}},
						},
						Aggregations: []qbtypes.TraceAggregation{
							{Expression: "p50(duration_nano)", Alias: "p50"},
							{Expression: "p95(duration_nano)", Alias: "p95"},
							{Expression: "p99(duration_nano)", Alias: "p99"},
							{Expression: "count()", Alias: "numCalls"},
							{Expression: "countIf(status_code = 2)", Alias: "errorCount"},
						},
						Order: []qbtypes.OrderBy{
							{Key: qbtypes.OrderByKey{TelemetryFieldKey: telemetrytypes.TelemetryFieldKey{Name: "p99"}}, Direction: qbtypes.OrderDirectionDesc},
						},
						Limit: req.Limit,
					},
				},
			},
		},
	}
	return &reqV5, nil
}

func (m *module) mapEntryPointOpsQueryRangeResp(resp *qbtypes.QueryRangeResponse) []servicetypesv1.OperationItem {
	if resp == nil || len(resp.Data.Results) == 0 {
		return []servicetypesv1.OperationItem{}
	}
	sd, ok := resp.Data.Results[0].(*qbtypes.ScalarData)
	if !ok || sd == nil {
		return []servicetypesv1.OperationItem{}
	}

	nameIdx := -1
	aggIdx := map[int]int{}
	for i, c := range sd.Columns {
		switch c.Type {
		case qbtypes.ColumnTypeGroup:
			if c.Name == "name" {
				nameIdx = i
			}
		case qbtypes.ColumnTypeAggregation:
			aggIdx[int(c.AggregationIndex)] = i
		}
	}

	out := make([]servicetypesv1.OperationItem, 0, len(sd.Data))
	for _, row := range sd.Data {
		item := servicetypesv1.OperationItem{
			Name:       fmt.Sprintf("%v", row[nameIdx]),
			P50:        toFloat(row, aggIdx[0]),
			P95:        toFloat(row, aggIdx[1]),
			P99:        toFloat(row, aggIdx[2]),
			NumCalls:   toUint64(row, aggIdx[3]),
			ErrorCount: toUint64(row, aggIdx[4]),
		}
		out = append(out, item)
	}
	return out
}

func (m *module) withServicesContext(ctx context.Context, functionName string) context.Context {
	comments := map[string]string{
		instrumentationtypes.TelemetrySignal:  telemetrytypes.SignalTraces.StringValue(),
		instrumentationtypes.CodeNamespace:    "services",
		instrumentationtypes.CodeFunctionName: functionName,
	}
	return ctxtypes.NewContextWithCommentVals(ctx, comments)
}
