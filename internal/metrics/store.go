package metrics

import (
	"context"

	"github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/pkg/types"
)

type wrappedEventStore struct {
	inner store.EventStore
	c     *Collector
}

func WrapEventStore(inner store.EventStore, c *Collector) store.EventStore {
	if inner == nil {
		return nil
	}
	if c == nil {
		c = New()
	}
	return &wrappedEventStore{inner: inner, c: c}
}

func (w *wrappedEventStore) AppendEvent(ctx context.Context, ev types.Event) error {
	if w.c != nil {
		w.c.IncEvent(ev.Type)
	}
	return w.inner.AppendEvent(ctx, ev)
}

func (w *wrappedEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return w.inner.QueryEvents(ctx, q)
}

func (w *wrappedEventStore) Close() error { return w.inner.Close() }
