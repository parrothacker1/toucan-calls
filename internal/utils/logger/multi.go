package logger

import "github.com/toucan/toucan-calls/internal/utils/events"

type MultiWriter struct {
	writers []events.EventWriter[Log]
}

func NewMultiWriter(writers ...events.EventWriter[Log]) *MultiWriter {
	return &MultiWriter{writers: writers}
}

func (mw *MultiWriter) Write(logs []Log) {
	for _, w := range mw.writers {
		w.Write(logs)
	}
}
