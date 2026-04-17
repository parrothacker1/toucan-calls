package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type lokiPushPayload struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

type LokiWriter struct {
	endpoint   string
	labels     map[string]string
	httpClient *http.Client
}

func NewLokiWriter(endpoint string, labels map[string]string) *LokiWriter {
	return &LokiWriter{
		endpoint: endpoint,
		labels:   labels,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (w *LokiWriter) Write(logs []Log) {
	if len(logs) == 0 {
		return
	}

	// Group logs by level (Loki requires unique label sets per stream)
	streamMap := make(map[LogLevel][]Log)
	for _, l := range logs {
		streamMap[l.Level] = append(streamMap[l.Level], l)
	}

	payload := lokiPushPayload{Streams: make([]lokiStream, 0, len(streamMap))}
	for level, entries := range streamMap {
		labels := make(map[string]string, len(w.labels)+1)
		for k, v := range w.labels {
			labels[k] = v
		}
		labels["level"] = strings.ToLower(level.String())

		values := make([][2]string, len(entries))
		for i, e := range entries {
			values[i] = [2]string{
				fmt.Sprintf("%d", e.Timestamp.UnixNano()),
				formatLogLine(e),
			}
		}
		payload.Streams = append(payload.Streams, lokiStream{
			Stream: labels,
			Values: values,
		})
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loki: marshal error: %v\n", err)
		return
	}

	resp, err := w.httpClient.Post(w.endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "loki: push error: %v\n", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "loki: unexpected status %d\n", resp.StatusCode)
	}
}

func formatLogLine(l Log) string {
	var b strings.Builder
	b.WriteString(l.Timestamp.Format(time.RFC3339))
	b.WriteString(" [")
	b.WriteString(l.Level.String())
	b.WriteString("] ")
	b.WriteString(l.Message)
	if len(l.Fields) > 0 {
		b.WriteString(" | ")
		for k, v := range l.Fields {
			fmt.Fprintf(&b, "%s=%v ", k, v)
		}
	}
	return b.String()
}
