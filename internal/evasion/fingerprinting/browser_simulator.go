package fingerprinting

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type BrowserSimulator struct {
	fingerprinter  *HTTPFingerprinter
	tlsFingerprint *TLSFingerprinter
	logger         *logrus.Logger

	mu             sync.RWMutex
	behaviors      map[string]*BrowserBehavior
	cookies        map[string][]*http.Cookie        
	activeSessions map[string]*BrowserSession      
}

type BrowserBehavior struct {
	Name             string
	MouseMovements   bool
	ScrollBehavior   bool
	ClickPatterns    bool
	FormInteractions bool
	AjaxRequests     bool
	PageLoadDelay    time.Duration
	InteractionDelay time.Duration
	ScrollDelay      time.Duration
	MouseSpeed       int
	ScrollSpeed      int
}

type BrowserSession struct {
	ID             string
	Profile        string
	Behavior       string
	StartTime      time.Time
	LastActivity   time.Time
	PageCount      int
	MouseMovements int
	Clicks         int
	Scrolls        int
	FormsFilled    int
	Cookies        []*http.Cookie
	LocalStorage   map[string]string
	SessionStorage map[string]string
}

func NewBrowserSimulator(httpFingerprinter *HTTPFingerprinter, tlsFingerprinter *TLSFingerprinter, logger *logrus.Logger) *BrowserSimulator {
	if logger == nil {
		logger = logrus.New()
	}

	bs := &BrowserSimulator{
		fingerprinter:  httpFingerprinter,
		tlsFingerprint: tlsFingerprinter,
		logger:         logger,
		behaviors:      make(map[string]*BrowserBehavior),
		cookies:        make(map[string][]*http.Cookie),
		activeSessions: make(map[string]*BrowserSession),
	}

	bs.initializeBehaviors()
	return bs
}

func (bs *BrowserSimulator) initializeBehaviors() {
	bs.behaviors["human_desktop"] = &BrowserBehavior{
		Name:             "human_desktop",
		MouseMovements:   true,
		ScrollBehavior:   true,
		ClickPatterns:    true,
		FormInteractions: true,
		AjaxRequests:     true,
		PageLoadDelay:    2 * time.Second,
		InteractionDelay: 500 * time.Millisecond,
		ScrollDelay:      300 * time.Millisecond,
		MouseSpeed:       5,
		ScrollSpeed:      3,
	}

	bs.behaviors["human_mobile"] = &BrowserBehavior{
		Name:             "human_mobile",
		MouseMovements:   false, 
		ScrollBehavior:   true,
		ClickPatterns:    true,
		FormInteractions: true,
		AjaxRequests:     true,
		PageLoadDelay:    3 * time.Second,
		InteractionDelay: 700 * time.Millisecond,
		ScrollDelay:      500 * time.Millisecond,
		MouseSpeed:       0,
		ScrollSpeed:      2,
	}

	bs.behaviors["automated_fast"] = &BrowserBehavior{
		Name:             "automated_fast",
		MouseMovements:   false,
		ScrollBehavior:   false,
		ClickPatterns:    false,
		FormInteractions: false,
		AjaxRequests:     false,
		PageLoadDelay:    100 * time.Millisecond,
		InteractionDelay: 50 * time.Millisecond,
		ScrollDelay:      0,
		MouseSpeed:       0,
		ScrollSpeed:      0,
	}
}

func (bs *BrowserSimulator) StartSession(profile, behavior string) (*BrowserSession, error) {
	sessionID, err := bs.generateSessionID()
	if err != nil {
		return nil, err
	}

	if _, ok := bs.behaviors[behavior]; !ok {
		return nil, fmt.Errorf("behavior profile not found: %s", behavior)
	}

	session := &BrowserSession{
		ID:             sessionID,
		Profile:        profile,
		Behavior:       behavior,
		StartTime:      time.Now(),
		LastActivity:   time.Now(),
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
	}

	bs.mu.Lock()
	bs.activeSessions[sessionID] = session
	bs.mu.Unlock()

	bs.logger.Infof("Started browser session %s with profile %s and behavior %s", sessionID, profile, behavior)
	return session, nil
}

func (bs *BrowserSimulator) EndSession(sessionID string) error {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	if _, exists := bs.activeSessions[sessionID]; !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}
	delete(bs.activeSessions, sessionID)
	delete(bs.cookies, sessionID)

	bs.logger.Infof("Ended browser session %s", sessionID)
	return nil
}

func (bs *BrowserSimulator) GenerateRequest(sessionID, method, url string) (*http.Request, error) {
	session, err := bs.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	if err := bs.fingerprinter.ApplyProfile(req, session.Profile); err != nil {
		return nil, err
	}

	bs.addSessionCookies(req, sessionID)

	bs.mu.Lock()
	session.LastActivity = time.Now()
	session.PageCount++
	bs.mu.Unlock()

	return req, nil
}

func (bs *BrowserSimulator) BuildClientForSession(sessionID string, timeout time.Duration) (*http.Client, error) {
	session, err := bs.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	return bs.fingerprinter.BuildClientForProfile(session.Profile, timeout)
}

func (bs *BrowserSimulator) ApplyBehaviorDelay(behavior string, phase string) {
	bs.mu.RLock()
	b, ok := bs.behaviors[behavior]
	bs.mu.RUnlock()
	if !ok {
		return
	}
	switch phase {
	case "page_load":
		time.Sleep(b.PageLoadDelay)
	case "interaction":
		time.Sleep(b.InteractionDelay)
	case "scroll":
		time.Sleep(b.ScrollDelay)
	}
}

func (bs *BrowserSimulator) AddCookie(sessionID string, cookie *http.Cookie) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.cookies[sessionID] = append(bs.cookies[sessionID], cookie)
}

func (bs *BrowserSimulator) GetCookies(sessionID string) []*http.Cookie {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	return bs.cookies[sessionID]
}

func (bs *BrowserSimulator) addSessionCookies(req *http.Request, sessionID string) {
	for _, cookie := range bs.GetCookies(sessionID) {
		req.AddCookie(cookie)
	}
}

func (bs *BrowserSimulator) GetSession(sessionID string) (*BrowserSession, error) {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	session, exists := bs.activeSessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	return session, nil
}

func (bs *BrowserSimulator) SetLocalStorage(sessionID, key, value string) error {
	s, err := bs.GetSession(sessionID)
	if err != nil {
		return err
	}
	bs.mu.Lock()
	s.LocalStorage[key] = value
	bs.mu.Unlock()
	return nil
}

func (bs *BrowserSimulator) GetLocalStorage(sessionID, key string) (string, bool, error) {
	s, err := bs.GetSession(sessionID)
	if err != nil {
		return "", false, err
	}
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	v, ok := s.LocalStorage[key]
	return v, ok, nil
}

func (bs *BrowserSimulator) SetSessionStorage(sessionID, key, value string) error {
	s, err := bs.GetSession(sessionID)
	if err != nil {
		return err
	}
	bs.mu.Lock()
	s.SessionStorage[key] = value
	bs.mu.Unlock()
	return nil
}

func (bs *BrowserSimulator) GetSessionStorage(sessionID, key string) (string, bool, error) {
	s, err := bs.GetSession(sessionID)
	if err != nil {
		return "", false, err
	}
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	v, ok := s.SessionStorage[key]
	return v, ok, nil
}

func (bs *BrowserSimulator) SimulateMouseMovement(sessionID string, behavior string) error {
	session, err := bs.GetSession(sessionID)
	if err != nil {
		return err
	}

	bs.mu.RLock()
	behaviorProfile, exists := bs.behaviors[behavior]
	bs.mu.RUnlock()
	if !exists {
		return fmt.Errorf("behavior profile not found: %s", behavior)
	}
	if !behaviorProfile.MouseMovements {
		return nil 
	}

	movements := bs.generateRandomMovements(behaviorProfile.MouseSpeed)
	for _, movement := range movements {
		time.Sleep(time.Duration(movement.Delay) * time.Millisecond)
		bs.mu.Lock()
		session.MouseMovements++
		session.LastActivity = time.Now()
		bs.mu.Unlock()
	}
	return nil
}

func (bs *BrowserSimulator) SimulateScroll(sessionID string, behavior string) error {
	session, err := bs.GetSession(sessionID)
	if err != nil {
		return err
	}

	bs.mu.RLock()
	behaviorProfile, exists := bs.behaviors[behavior]
	bs.mu.RUnlock()
	if !exists {
		return fmt.Errorf("behavior profile not found: %s", behavior)
	}
	if !behaviorProfile.ScrollBehavior {
		return nil 
	}

	scrolls := bs.generateRandomScrolls(behaviorProfile.ScrollSpeed)
	for _, scroll := range scrolls {
		_ = scroll 
		time.Sleep(time.Duration(behaviorProfile.ScrollDelay))
		bs.mu.Lock()
		session.Scrolls++
		session.LastActivity = time.Now()
		bs.mu.Unlock()
	}
	return nil
}

func (bs *BrowserSimulator) RecordClick(sessionID string) error {
	s, err := bs.GetSession(sessionID)
	if err != nil {
		return err
	}
	bs.mu.Lock()
	s.Clicks++
	s.LastActivity = time.Now()
	bs.mu.Unlock()
	return nil
}


func (bs *BrowserSimulator) RecordFormFill(sessionID string) error {
	s, err := bs.GetSession(sessionID)
	if err != nil {
		return err
	}
	bs.mu.Lock()
	s.FormsFilled++
	s.LastActivity = time.Now()
	bs.mu.Unlock()
	return nil
}

func (bs *BrowserSimulator) generateRandomMovements(speed int) []struct {
	X int
	Y int
	Delay int
} {
	movements := make([]struct {
		X int
		Y int
		Delay int
	}, 10)

	for i := range movements {
		randX, _ := rand.Int(rand.Reader, big.NewInt(100))
		randY, _ := rand.Int(rand.Reader, big.NewInt(100))
		randDelay, _ := rand.Int(rand.Reader, big.NewInt(200))

		_ = speed 

		movements[i] = struct {
			X int
			Y int
			Delay int
		}{
			X:     int(randX.Int64()),
			Y:     int(randY.Int64()),
			Delay: int(randDelay.Int64()) + 50,
		}
	}
	return movements
}


func (bs *BrowserSimulator) generateRandomScrolls(speed int) []struct {
	Distance int
	Delay    int
} {
	scrolls := make([]struct {
		Distance int
		Delay    int
	}, 5)

	for i := range scrolls {
		randDistance, _ := rand.Int(rand.Reader, big.NewInt(500))
		randDelay, _ := rand.Int(rand.Reader, big.NewInt(300))

		_ = speed 

		scrolls[i] = struct {
			Distance int
			Delay    int
		}{
			Distance: int(randDistance.Int64()) + 100,
			Delay:    int(randDelay.Int64()) + 100,
		}
	}
	return scrolls
}

func (bs *BrowserSimulator) GetActiveSessions() []*BrowserSession {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	sessions := make([]*BrowserSession, 0, len(bs.activeSessions))
	for _, session := range bs.activeSessions {
		sessions = append(sessions, session)
	}
	return sessions
}

func (bs *BrowserSimulator) CleanupSessions(maxAge time.Duration) {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	now := time.Now()
	for id, session := range bs.activeSessions {
		if now.Sub(session.LastActivity) > maxAge {
			delete(bs.activeSessions, id)
			delete(bs.cookies, id)
			bs.logger.Infof("Cleaned up expired session %s", id)
		}
	}
}

func (bs *BrowserSimulator) GetStats() map[string]interface{} {
	bs.mu.RLock()
	defer bs.mu.RUnlock()

	return map[string]interface{}{
		"active_sessions": len(bs.activeSessions),
		"behavior_count":  len(bs.behaviors),
	}
}

func (bs *BrowserSimulator) generateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
