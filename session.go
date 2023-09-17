package main

import (
	"github.com/hiro942/elden-server/model/enums"
	"sync"
)

type SessionPool struct {
	SessionMap map[string]*Session // key: H-IMSI
	Satellite  *Satellite
	mu         *sync.Mutex
}

type Session struct {
	ClientID            string
	ClientMacAddr       string
	ClientSocket        string // 终端套接字
	ClientPosition      int64
	AccessType          enums.AccessType
	PreviousSatelliteID string
	SessionKey          []byte
	ExpirationDate      int64
	StartAt             int64
}

func NewSessions(satellite *Satellite) *SessionPool {
	return &SessionPool{
		SessionMap: make(map[string]*Session),
		Satellite:  satellite,
		mu:         &sync.Mutex{},
	}
}

func (s *SessionPool) GetSession(clientID string) *Session {
	return s.SessionMap[clientID]
}

func (s *SessionPool) SetSession(clientID string, session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SessionMap[clientID] = session
}
