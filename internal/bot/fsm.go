package bot

import "sync"

// step is the current stage of the /roll dialog for a chat.
type step int

const (
	stepIdle step = iota
	stepProvider
	stepMask
	stepBudget
	stepConfirm
	stepRunning
	stepResult
	stepAttachVM
)

// dialogState is the per-chat conversation state.
type dialogState struct {
	Step     step
	Provider string
	Mask     string
	Budget   int
	MsgID    int // id of the editable progress/wizard message

	// result of a completed roll
	ResultIP     string
	ResultResID  string
	ResultPoolID int64
}

// FSM holds dialog state per chat behind a mutex.
type FSM struct {
	mu     sync.Mutex
	states map[int64]*dialogState
}

func NewFSM() *FSM { return &FSM{states: make(map[int64]*dialogState)} }

// Get returns the state for chatID, creating an idle one if absent.
func (f *FSM) Get(chatID int64) *dialogState {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.states[chatID]
	if !ok {
		st = &dialogState{Step: stepIdle}
		f.states[chatID] = st
	}
	return st
}

// Update mutates the state for chatID atomically.
func (f *FSM) Update(chatID int64, fn func(*dialogState)) *dialogState {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.states[chatID]
	if !ok {
		st = &dialogState{Step: stepIdle}
		f.states[chatID] = st
	}
	fn(st)
	return st
}

// Clear resets the dialog for chatID.
func (f *FSM) Clear(chatID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.states, chatID)
}
