package notify

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

type fakeStore struct {
	m    map[string]int
	sets int
}

func (f *fakeStore) GetForumTopic(_ context.Context, name string) (int, bool, error) {
	id, ok := f.m[name]
	return id, ok, nil
}

func (f *fakeStore) SetForumTopic(_ context.Context, name string, id int) error {
	f.m[name] = id
	f.sets++
	return nil
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestDisabledIsNoop(t *testing.T) {
	n := New(0, false, &fakeStore{m: map[string]int{}}, quiet())
	if n.Enabled() {
		t.Fatal("notifier with chat_id 0 must be disabled")
	}
	// must not panic / touch the (nil) bot when disabled
	n.Caught(context.Background(), nil, "acc", "1.2.3.4", "1.2.3.*", 3)
	n.NoMatch(context.Background(), nil, "acc", "1.2.3.*", 5)
	n.Attached(context.Background(), nil, "acc", "1.2.3.4", "vm1")
	n.Failed(context.Background(), nil, "acc", "boom")
}

func TestEnsureTopicPrefersStore(t *testing.T) {
	fs := &fakeStore{m: map[string]int{"Timeweb · prod": 7}}
	n := New(123, true, fs, quiet())
	// store hit → returns thread id without ever touching the bot
	if got := n.ensureTopic(context.Background(), nil, "Timeweb · prod"); got != 7 {
		t.Fatalf("ensureTopic = %d, want 7", got)
	}
	// cached now → still no bot, no extra store writes
	if got := n.ensureTopic(context.Background(), nil, "Timeweb · prod"); got != 7 {
		t.Fatalf("cached ensureTopic = %d, want 7", got)
	}
	if fs.sets != 0 {
		t.Errorf("store should not have been written on a hit, sets=%d", fs.sets)
	}
}

func TestEscAndTopicName(t *testing.T) {
	if got := esc("a<b>&c"); got != "a&lt;b&gt;&amp;c" {
		t.Errorf("esc = %q", got)
	}
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'x'
	}
	if got := topicName(string(long)); len(got) != 128 {
		t.Errorf("topicName len = %d, want 128", len(got))
	}
}
