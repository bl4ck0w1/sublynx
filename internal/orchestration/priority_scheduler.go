package orchestration

import (
	"container/heap"
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"
	"github.com/sirupsen/logrus"
)

type PriorityScheduler struct {
	tasks         *PriorityQueue
	logger        *logrus.Logger
	mu            sync.RWMutex
	maxConcurrent int
	activeTasks map[string]*Task        
	queuedTasks map[string]*Task     
	taskCounter int
	baseBackoff time.Duration
	maxBackoff  time.Duration
	jitterPct   float64 
}

type Task struct {
	ID           string
	Priority     int
	Created      time.Time
	ScheduledFor time.Time
	Type         string
	Data         interface{}
	Context    context.Context
	CancelFunc context.CancelFunc
	Retries    int
	MaxRetries int
	index int 
}

type PriorityQueue []*Task

func NewPriorityScheduler(logger *logrus.Logger) *PriorityScheduler {
	if logger == nil {
		logger = logrus.New()
	}

	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	return &PriorityScheduler{
		tasks:         &pq,
		logger:        logger,
		maxConcurrent: 10,
		activeTasks:   make(map[string]*Task),
		queuedTasks:   make(map[string]*Task),

		baseBackoff: 1 * time.Second,
		maxBackoff:  2 * time.Minute,
		jitterPct:   0.2,
	}
}

func (ps *PriorityScheduler) ScheduleTask(taskType string, priority int, data interface{}, maxRetries int) (string, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.taskCounter++
	taskID := fmt.Sprintf("task_%d_%d", time.Now().Unix(), ps.taskCounter)

	task := &Task{
		ID:           taskID,
		Priority:     priority,
		Created:      time.Now(),
		ScheduledFor: time.Now(),
		Type:         taskType,
		Data:         data,
		MaxRetries:   maxRetries,
		index:        -1,
	}

	heap.Push(ps.tasks, task)
	ps.queuedTasks[taskID] = task

	ps.logger.Infof("Task scheduled: %s (priority: %d)", taskID, priority)
	return taskID, nil
}

func (ps *PriorityScheduler) ScheduleDelayedTask(taskType string, priority int, data interface{}, delay time.Duration, maxRetries int) (string, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	ps.taskCounter++
	taskID := fmt.Sprintf("task_%d_%d", time.Now().Unix(), ps.taskCounter)

	task := &Task{
		ID:           taskID,
		Priority:     priority,
		Created:      time.Now(),
		ScheduledFor: time.Now().Add(delay),
		Type:         taskType,
		Data:         data,
		MaxRetries:   maxRetries,
		index:        -1,
	}

	heap.Push(ps.tasks, task)
	ps.queuedTasks[taskID] = task

	ps.logger.Infof("Delayed task scheduled: %s (priority: %d, delay: %v)", taskID, priority, delay)
	return taskID, nil
}

func (ps *PriorityScheduler) GetNextTask() (*Task, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	if len(ps.activeTasks) >= ps.maxConcurrent {
		return nil, fmt.Errorf("maximum concurrent tasks reached (%d)", ps.maxConcurrent)
	}

	if ps.tasks.Len() == 0 {
		return nil, fmt.Errorf("no tasks available")
	}

	head := (*ps.tasks)[0]
	if head.ScheduledFor.After(time.Now()) {
		return nil, fmt.Errorf("no tasks ready for execution")
	}

	task := heap.Pop(ps.tasks).(*Task)
	task.index = -1
	delete(ps.queuedTasks, task.ID)

	if task.Context == nil || task.CancelFunc == nil {
		ctx, cancel := context.WithCancel(context.Background())
		task.Context = ctx
		task.CancelFunc = cancel
	}

	ps.activeTasks[task.ID] = task
	return task, nil
}

func (ps *PriorityScheduler) CompleteTask(taskID string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	task, exists := ps.activeTasks[taskID]
	if !exists {
		return fmt.Errorf("task not found: %s", taskID)
	}

	if task.CancelFunc != nil {
		task.CancelFunc()
	}
	delete(ps.activeTasks, taskID)
	ps.logger.Infof("Task completed: %s", taskID)
	return nil
}

func (ps *PriorityScheduler) FailTask(taskID string, errorMsg string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	task, exists := ps.activeTasks[taskID]
	if !exists {
		return fmt.Errorf("task not found: %s", taskID)
	}

	task.Retries++
	if task.CancelFunc != nil {
		task.CancelFunc()
	}

	if task.Retries > task.MaxRetries {
		delete(ps.activeTasks, taskID)
		ps.logger.Warnf("Task failed permanently: %s (error: %s)", taskID, errorMsg)
		return nil
	}
	backoff := ps.jitteredBackoff(task.Retries)

	task.ScheduledFor = time.Now().Add(backoff)
	delete(ps.activeTasks, taskID)
	heap.Push(ps.tasks, task)
	ps.queuedTasks[taskID] = task
	ps.logger.Warnf("Task failed, rescheduling: %s (retry %d/%d, backoff: %v, error: %s)",
		taskID, task.Retries, task.MaxRetries, backoff, errorMsg)

	return nil
}

func (ps *PriorityScheduler) CancelTask(taskID string) error {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if task, exists := ps.activeTasks[taskID]; exists {
		if task.CancelFunc != nil {
			task.CancelFunc()
		}
		delete(ps.activeTasks, taskID)
		ps.logger.Infof("Task cancelled: %s", taskID)
		return nil
	}
	if task, exists := ps.queuedTasks[taskID]; exists {
		if task.index >= 0 && task.index < ps.tasks.Len() {
			heap.Remove(ps.tasks, task.index)
		}
		delete(ps.queuedTasks, taskID)
		ps.logger.Infof("Task cancelled: %s", taskID)
		return nil
	}

	return fmt.Errorf("task not found: %s", taskID)
}

func (ps *PriorityScheduler) SetMaxConcurrent(max int) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if max <= 0 {
		max = 1
	}
	ps.maxConcurrent = max
}

func (ps *PriorityScheduler) GetStats() map[string]interface{} {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	return map[string]interface{}{
		"queued_tasks":     ps.tasks.Len(),
		"active_tasks":     len(ps.activeTasks),
		"max_concurrent":   ps.maxConcurrent,
		"total_scheduled":  ps.taskCounter,
		"base_backoff":     ps.baseBackoff.String(),
		"max_backoff":      ps.maxBackoff.String(),
		"backoff_jitter_p": ps.jitterPct,
	}
}

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	if pq[i].Priority == pq[j].Priority {
		return pq[i].ScheduledFor.Before(pq[j].ScheduledFor)
	}
	return pq[i].Priority > pq[j].Priority
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *PriorityQueue) Push(x interface{}) {
	item := x.(*Task)
	item.index = len(*pq)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	item.index = -1 
	old[n-1] = nil  
	*pq = old[0 : n-1]
	return item
}

func (ps *PriorityScheduler) jitteredBackoff(retries int) time.Duration {
	if retries < 1 {
		retries = 1
	}
	backoff := ps.baseBackoff * (1 << (retries - 1))
	if backoff > ps.maxBackoff {
		backoff = ps.maxBackoff
	}
	if ps.jitterPct > 0 {
		j := ps.jitterPct
		delta := time.Duration(float64(backoff) * j)
		off := time.Duration(rand.Int63n(int64(2*delta+1))) - delta
		backoff += off
		if backoff < 0 {
			backoff = 0
		}
	}
	return backoff
}
