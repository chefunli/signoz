package model

import "time"

type SpanItemV2 struct {
	TimeUnixNano      time.Time          `ch:"timestamp" json:"timestamp"`
	DurationNano      uint64             `ch:"duration_nano" json:"duration_nano"`
	SpanID            string             `ch:"span_id" json:"span_id"`
	TraceID           string             `ch:"trace_id" json:"trace_id"`
	HasError          bool               `ch:"has_error" json:"has_error"`
	Kind              int8               `ch:"kind" json:"kind"`
	ServiceName       string             `ch:"resource_string_service$$name" json:"resource_string_service$$name"`
	Name              string             `ch:"name" json:"name"`
	References        string             `ch:"references" json:"references"`
	Attributes_string map[string]string  `ch:"attributes_string" json:"attributes_string"`
	Attributes_number map[string]float64 `ch:"attributes_number" json:"attributes_number"`
	Attributes_bool   map[string]bool    `ch:"attributes_bool" json:"attributes_bool"`
	Resources_string  map[string]string  `ch:"resources_string" json:"resources_string"`
	Events            []string           `ch:"events" json:"events"`
	StatusMessage     string             `ch:"status_message" json:"status_message"`
	StatusCodeString  string             `ch:"status_code_string" json:"status_code_string"`
	SpanKind          string             `ch:"kind_string" json:"kind_string"`
	ParentSpanId      string             `ch:"parent_span_id" json:"parent_span_id"`
}

type TraceSummary struct {
	TraceID  string    `ch:"trace_id" json:"trace_id"`
	Start    time.Time `ch:"start" json:"start"`
	End      time.Time `ch:"end" json:"end"`
	NumSpans uint64    `ch:"num_spans" json:"num_spans"`
}

// AttributeValue looks up an attribute across string, number, and bool maps in priority order.
func (s SpanItemV2) AttributeValue(name string) any {
	if v, ok := s.Attributes_string[name]; ok {
		return v
	}
	if v, ok := s.Attributes_number[name]; ok {
		return v
	}
	if v, ok := s.Attributes_bool[name]; ok {
		return v
	}
	return nil
}
