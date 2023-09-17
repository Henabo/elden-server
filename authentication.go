package main

type Authentication struct {
	SessionPool *SessionPool
}

func NewAuthentication(sessionPool *SessionPool) *Authentication {
	return &Authentication{SessionPool: sessionPool}
}
