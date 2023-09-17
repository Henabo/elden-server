package main

import "sync"

type Cache struct {
	SatelliteSockets  map[string]string
	ClientSockets     map[string]string
	RandNums          map[string]int    // 认证随机数 key = H-IMSI
	ClientHandoverSet map[string]string // 交接集合 H-IMSI -> PreviousSatellite
	mu                *sync.Mutex
}

func NewCache() *Cache {
	c := &Cache{
		SatelliteSockets:  map[string]string{},
		ClientSockets:     map[string]string{},
		RandNums:          make(map[string]int),
		ClientHandoverSet: make(map[string]string),
		mu:                &sync.Mutex{},
	}
	c.SetSatelliteSocket("s0", "localhost:19999")
	c.SetSatelliteSocket("s1", "localhost:19998")
	return c
}

func (c *Cache) GetSatelliteSocket(sid string) string {
	return c.SatelliteSockets[sid]
}

func (c *Cache) SetSatelliteSocket(sid string, socket string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SatelliteSockets[sid] = socket
}

func (c *Cache) GetClientSocket(cid string) string {
	return c.ClientSockets[cid]
}

func (c *Cache) SetClientSocket(cid string, socket string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ClientSockets[cid] = socket
}

func (c *Cache) GetRandNumber(clientID string) int {
	return c.RandNums[clientID]
}

func (c *Cache) SetRandNumber(clientID string, rand int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RandNums[clientID] = rand
}

func (c *Cache) GetClientHandoverSet(clientID string) string {
	return c.ClientHandoverSet[clientID]
}

func (c *Cache) SetClientHandoverSet(clientID string, previousSID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ClientHandoverSet[clientID] = previousSID
}
