package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

const (
	endpoint = "http://127.0.0.1:5080"
	orgID    = "default"
	username = "root@example.com"
	password = "Complexpass#123"
)

func main() {
	fmt.Println("=== Generating OTLP test data for OpenObserve ===")

	// Generate traces
	fmt.Println("\n[1/3] Generating traces...")
	generateTraces()

	// Generate logs
	fmt.Println("\n[2/3] Generating logs...")
	generateLogs()

	// Generate metrics
	fmt.Println("\n[3/3] Generating metrics...")
	generateMetrics()

	fmt.Println("\n=== Done! Verifying streams...")
	verifyStreams()
}

func generateTraces() {
	now := time.Now()
	services := []string{"frontend", "api-server", "payment-service", "user-service", "notification-service"}
	operations := []string{"HTTP GET /api/users", "HTTP POST /api/orders", "HTTP GET /api/products", "gRPC GetPayment", "DB SELECT users", "HTTP GET /api/health"}

	var spans []map[string]any

	for i := 0; i < 50; i++ {
		traceID := randomHex(32)
		spanCount := rand.Intn(5) + 2
		rootSpanID := randomHex(16)
		service := services[rand.Intn(len(services))]
		operation := operations[rand.Intn(len(operations))]
		startTime := now.Add(-time.Duration(rand.Intn(3600)) * time.Second)
		duration := rand.Int63n(5000000000) + 1000000 // 1ms - 5s in nanoseconds

		// Root span
		rootSpan := map[string]any{
			"trace_id":            traceID,
			"span_id":             rootSpanID,
			"parent_span_id":      "",
			"operation_name":      operation,
			"service_name":        service,
			"start_time":          startTime.UnixNano(),
			"end_time":            startTime.Add(time.Duration(duration)).UnixNano(),
			"duration":            duration,
			"span_kind":           "SERVER",
			"status_code":         "STATUS_CODE_OK",
			"status_message":      "",
			"attributes":          map[string]any{"http.method": "GET", "http.status_code": 200, "http.url": "/api/v1/test"},
			"resource_attributes": map[string]any{"service.name": service, "service.version": "1.0.0", "deployment.environment": "production"},
			"events":              []any{},
			"links":               []any{},
		}
		spans = append(spans, rootSpan)

		// Child spans
		parentID := rootSpanID
		for j := 1; j < spanCount; j++ {
			childSpanID := randomHex(16)
			childStart := startTime.Add(time.Duration(rand.Int63n(duration/2)) * time.Nanosecond)
			childDuration := rand.Int63n(duration/2) + 500000

			childService := services[rand.Intn(len(services))]
			childOp := operations[rand.Intn(len(operations))]

			childSpan := map[string]any{
				"trace_id":            traceID,
				"span_id":             childSpanID,
				"parent_span_id":      parentID,
				"operation_name":      childOp,
				"service_name":        childService,
				"start_time":          childStart.UnixNano(),
				"end_time":            childStart.Add(time.Duration(childDuration)).UnixNano(),
				"duration":            childDuration,
				"span_kind":           "INTERNAL",
				"status_code":         "STATUS_CODE_OK",
				"status_message":      "",
				"attributes":          map[string]any{"db.system": "postgresql", "db.statement": "SELECT * FROM users WHERE id = $1"},
				"resource_attributes": map[string]any{"service.name": childService, "service.version": "1.0.0", "deployment.environment": "production"},
				"events":              []any{},
				"links":               []any{},
			}
			spans = append(spans, childSpan)
			parentID = childSpanID
		}
	}

	// Send as individual span records (OpenObserve format)
	body := map[string]any{
		"resourceSpans": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]any{
						{"key": "service.name", "value": map[string]any{"stringValue": "test-service"}},
					},
				},
				"scopeSpans": []map[string]any{
					{
						"spans": func() []map[string]any {
							var otlpSpans []map[string]any
							for _, s := range spans {
								otlpSpans = append(otlpSpans, map[string]any{
									"traceId":           s["trace_id"],
									"spanId":            s["span_id"],
									"parentSpanId":      s["parent_span_id"],
									"name":              s["operation_name"],
									"kind":              2,
									"startTimeUnixNano": fmt.Sprintf("%d", s["start_time"]),
									"endTimeUnixNano":   fmt.Sprintf("%d", s["end_time"]),
									"attributes": func() []map[string]any {
										var attrs []map[string]any
										for k, v := range s["attributes"].(map[string]any) {
											switch val := v.(type) {
											case int:
												attrs = append(attrs, map[string]any{
													"key":   k,
													"value": map[string]any{"intValue": fmt.Sprintf("%d", val)},
												})
											default:
												attrs = append(attrs, map[string]any{
													"key":   k,
													"value": map[string]any{"stringValue": fmt.Sprintf("%v", val)},
												})
											}
										}
										return attrs
									}(),
									"status": map[string]any{"code": 1},
								})
							}
							return otlpSpans
						}(),
					},
				},
			},
		},
	}

	data, _ := json.Marshal(body)
	sendOTLP("traces", data)
	fmt.Printf("  Sent %d spans across multiple traces\n", len(spans))
}

func generateLogs() {
	now := time.Now()
	services := []string{"frontend", "api-server", "payment-service"}
	levels := []string{"INFO", "WARN", "ERROR", "DEBUG"}
	messages := []string{
		"Request processed successfully",
		"Database connection established",
		"Cache miss for key user:123",
		"Slow query detected: 2.3s",
		"Rate limit approaching threshold",
		"Payment processed for order #456",
		"User authentication successful",
		"Background job completed",
	}

	var logRecords []map[string]any
	for i := 0; i < 100; i++ {
		service := services[rand.Intn(len(services))]
		level := levels[rand.Intn(len(levels))]
		msg := messages[rand.Intn(len(messages))]
		ts := now.Add(-time.Duration(rand.Intn(3600)) * time.Second)

		logRecords = append(logRecords, map[string]any{
			"timestamp":     ts.UnixNano(),
			"severity_text": level,
			"body":          map[string]any{"stringValue": fmt.Sprintf("[%s] %s: %s", level, service, msg)},
			"attributes": []map[string]any{
				{"key": "service.name", "value": map[string]any{"stringValue": service}},
				{"key": "log.level", "value": map[string]any{"stringValue": level}},
				{"key": "host.name", "value": map[string]any{"stringValue": "test-host-01"}},
			},
			"traceId": randomHex(32),
			"spanId":  randomHex(16),
		})
	}

	body := map[string]any{
		"resourceLogs": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]any{
						{"key": "service.name", "value": map[string]any{"stringValue": "test-service"}},
					},
				},
				"scopeLogs": []map[string]any{
					{
						"logRecords": logRecords,
					},
				},
			},
		},
	}

	data, _ := json.Marshal(body)
	sendOTLP("logs", data)
	fmt.Printf("  Sent %d log records\n", len(logRecords))
}

func generateMetrics() {
	now := time.Now()
	services := []string{"frontend", "api-server", "payment-service"}

	var dataPoints []map[string]any
	for i := 0; i < 60; i++ {
		service := services[rand.Intn(len(services))]
		ts := now.Add(-time.Duration(i*60) * time.Second)

		// Gauge: request latency
		dataPoints = append(dataPoints, map[string]any{
			"time":  ts.UnixNano(),
			"value": float64(rand.Intn(500)) + 10.0,
			"attributes": []map[string]any{
				{"key": "service.name", "value": map[string]any{"stringValue": service}},
				{"key": "metric_type", "value": map[string]any{"stringValue": "gauge"}},
			},
		})
	}

	// Sum: request count
	for i := 0; i < 60; i++ {
		service := services[rand.Intn(len(services))]
		ts := now.Add(-time.Duration(i*60) * time.Second)

		dataPoints = append(dataPoints, map[string]any{
			"time":  ts.UnixNano(),
			"value": float64(rand.Intn(1000)),
			"attributes": []map[string]any{
				{"key": "service.name", "value": map[string]any{"stringValue": service}},
				{"key": "metric_type", "value": map[string]any{"stringValue": "sum"}},
			},
		})
	}

	body := map[string]any{
		"resourceMetrics": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]any{
						{"key": "service.name", "value": map[string]any{"stringValue": "test-service"}},
					},
				},
				"scopeMetrics": []map[string]any{
					{
						"metrics": []map[string]any{
							{
								"name":        "http_request_duration_seconds",
								"description": "HTTP request duration",
								"unit":        "s",
								"gauge": map[string]any{
									"dataPoints": func() []map[string]any {
										var dps []map[string]any
										for _, dp := range dataPoints[:60] {
											dps = append(dps, map[string]any{
												"timeUnixNano": fmt.Sprintf("%d", dp["time"]),
												"asDouble":     dp["value"],
												"attributes":   dp["attributes"],
											})
										}
										return dps
									}(),
								},
							},
							{
								"name":        "http_requests_total",
								"description": "Total HTTP requests",
								"unit":        "1",
								"sum": map[string]any{
									"dataPoints": func() []map[string]any {
										var dps []map[string]any
										for _, dp := range dataPoints[60:] {
											dps = append(dps, map[string]any{
												"timeUnixNano": fmt.Sprintf("%d", dp["time"]),
												"asDouble":     dp["value"],
												"attributes":   dp["attributes"],
											})
										}
										return dps
									}(),
									"aggregationTemporality": 2,
									"isMonotonic":             true,
								},
							},
						},
					},
				},
			},
		},
	}

	data, _ := json.Marshal(body)
	sendOTLP("metrics", data)
	fmt.Printf("  Sent 2 metrics with %d data points each\n", 60)
}

func sendOTLP(signal string, data []byte) {
	url := fmt.Sprintf("%s/api/%s/v1/%s", endpoint, orgID, signal)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("  ERROR sending %s: %v\n", signal, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		fmt.Printf("  ERROR: %s returned %d: %s\n", signal, resp.StatusCode, buf.String())
		return
	}
	fmt.Printf("  ✓ %s ingested successfully (HTTP %d)\n", signal, resp.StatusCode)
}

func verifyStreams() {
	url := fmt.Sprintf("%s/api/%s/streams", endpoint, orgID)
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(username, password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	if list, ok := result["list"].([]any); ok {
		fmt.Printf("  Found %d streams:\n", len(list))
		for _, s := range list {
			if m, ok := s.(map[string]any); ok {
				fmt.Printf("    - %s (type: %s)\n", m["name"], m["stream_type"])
			}
		}
	}
}

func randomHex(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hex[rand.Intn(16)]
	}
	return string(b)
}
