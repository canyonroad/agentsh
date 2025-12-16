package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestStore_FlushesOnBatchSize(t *testing.T) {
	var mu sync.Mutex
	var got [][]types.Event

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var batch []types.Event
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Fatalf("decode: %v", err)
		}
		mu.Lock()
		got = append(got, batch)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	st, err := New(srv.URL, 2, 1*time.Hour, 2*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	ev1 := types.Event{ID: "1", Timestamp: time.Now().UTC(), Type: "x", SessionID: "s"}
	ev2 := types.Event{ID: "2", Timestamp: time.Now().UTC(), Type: "y", SessionID: "s"}
	if err := st.AppendEvent(context.Background(), ev1); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendEvent(context.Background(), ev2); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || len(got[0]) != 2 {
		t.Fatalf("expected 1 batch of 2, got %#v", got)
	}
}
