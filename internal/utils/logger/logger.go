// Package logger provides structured, async logging.
package logger

import (
	"fmt"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/toucan/toucan-calls/internal/utils/events"
)

type LogLevel int

const (
	Error LogLevel = iota
	Warn
	Info
	Debug
	Trace
)

func (l LogLevel) String() string {
	switch l {
	case Error:
		return "ERROR"
	case Warn:
		return "WARN"
	case Info:
		return "INFO"
	case Debug:
		return "DEBUG"
	case Trace:
		return "TRACE"
	default:
		return "UNKNOWN"
	}
}

type Fields map[string]any

type Log struct {
	Timestamp time.Time
	Message   string
	Level     LogLevel
	Fields    Fields
}

type Logger struct {
	Events *events.EventQueue[Log]
	writer events.EventWriter[Log]
	fields Fields
}

type LoggerOpts struct {
	Filename     string
	CustomWriter events.EventWriter[Log]
}

type DefaultEventWriter struct {
	file *os.File
}

func NewDefaultWriter(filename string) (*DefaultEventWriter, error) {
	if filename == "" {
		return &DefaultEventWriter{file: os.Stdout}, nil
	}
	f, err := os.OpenFile(filename,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644)
	if err != nil {
		return nil, err
	}
	return &DefaultEventWriter{file: f}, nil
}

func (w *DefaultEventWriter) Write(logs []Log) {
	for _, log := range logs {
		ts := log.Timestamp.Format(time.RFC3339)
		var b strings.Builder
		b.WriteString(ts)
		b.WriteString(" [")
		b.WriteString(log.Level.String())
		b.WriteString("] ")
		b.WriteString(log.Message)
		if len(log.Fields) > 0 {
			b.WriteString(" | ")
			for k, v := range log.Fields {
				fmt.Fprintf(&b, "%s=%v ", k, v)
			}
		}
		b.WriteString("\n")
		w.file.WriteString(b.String())
	}
}

func NewLogger(opts LoggerOpts) *Logger {
	writer := opts.CustomWriter
	if writer == nil {
		w, err := NewDefaultWriter(opts.Filename)
		if err != nil {
			panic(err)
		}
		writer = w
	}
	queueOpts := &events.EventOptions{
		Capacity:       1024,
		NodeSize:       64,
		WriteThreshold: 10,
		Write:          true,
	}

	q := events.NewEventQueue(queueOpts, writer)

	return &Logger{
		Events: q,
		writer: writer,
		fields: make(Fields),
	}
}

func (l *Logger) log(level LogLevel, msg string, fields Fields) {
	entry := Log{
		Timestamp: time.Now(),
		Message:   msg,
		Level:     level,
		Fields:    fields,
	}
	l.Events.Push(entry)
}

func (l *Logger) Trace(msg string) { l.log(Trace, msg, l.fields) }
func (l *Logger) Debug(msg string) { l.log(Debug, msg, l.fields) }
func (l *Logger) Info(msg string)  { l.log(Info, msg, l.fields) }
func (l *Logger) Warn(msg string)  { l.log(Warn, msg, l.fields) }
func (l *Logger) Error(msg string) { l.log(Error, msg, l.fields) }

func (l *Logger) Fatal(msg string) {
	l.Error(msg)
	l.Events.Reset(true)
	os.Exit(1)
}

func (l *Logger) Tracef(format string, args ...any) {
	l.Trace(fmt.Sprintf(format, args...))
}
func (l *Logger) Debugf(format string, args ...any) {
	l.Debug(fmt.Sprintf(format, args...))
}
func (l *Logger) Infof(format string, args ...any) {
	l.Info(fmt.Sprintf(format, args...))
}
func (l *Logger) Warnf(format string, args ...any) {
	l.Warn(fmt.Sprintf(format, args...))
}
func (l *Logger) Errorf(format string, args ...any) {
	l.Error(fmt.Sprintf(format, args...))
}
func (l *Logger) Fatalf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.Fatal(msg)
}

func (l *Logger) Print(args ...any)   { l.Info(fmt.Sprint(args...)) }
func (l *Logger) Println(args ...any) { l.Info(fmt.Sprintln(args...)) }
func (l *Logger) Printf(format string, args ...any) {
	l.Info(fmt.Sprintf(format, args...))
}

func (l *Logger) WithField(key string, value any) *Logger {
	return l.WithFields(Fields{key: value})
}

func (l *Logger) WithFields(f Fields) *Logger {
	newFields := make(Fields, len(l.fields)+len(f))
	maps.Copy(newFields, l.fields)
	maps.Copy(newFields, f)
	return &Logger{
		Events: l.Events,
		writer: l.writer,
		fields: newFields,
	}
}
