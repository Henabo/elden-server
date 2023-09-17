package main

import (
	"fmt"
	"github.com/hiro942/elden-server/config"
)

type URL struct {
	Cache *Cache
}

func NewURL(cache *Cache) *URL {
	return &URL{Cache: cache}
}

func (url *URL) RegisterSatellite() string {
	return config.Conf.FabricAppHostPath + "/node/satellite/register"
}

func (url *URL) UpdateClientAuthStatus() string {
	return config.Conf.FabricAppHostPath + "/node/user/changeAuthStatus"
}

func (url *URL) CreateAccessRecord() string {
	return config.Conf.FabricAppHostPath + "/node/user/accessRecord"
}

func (url *URL) QueryClientPublicKey(id string, macAddr string) string {
	return config.Conf.FabricAppHostPath + fmt.Sprintf("/node/user/publicKey?id=%s&macAddr=%s", id, macAddr)
}

func (url *URL) QuerySatellitePublicKey(id string) string {
	return config.Conf.FabricAppHostPath + fmt.Sprintf("/node/satellite/publicKey?id=%s", id)
}

func (url *URL) QueryNodeByID(id string) string {
	return config.Conf.FabricAppHostPath + fmt.Sprintf("/node/search?id=%s", id)
}

func (url *URL) SendNewSatelliteIDToUser(clientID string, newSatelliteID string) string {
	return fmt.Sprintf("http://%s/auth/prehandover/new_satellite?id=%s", url.Cache.GetClientSocket(clientID), newSatelliteID)
}

func (url *URL) RequestForClientLocation(clientID string) string {
	return fmt.Sprintf("http://%s/auth/prehandover/location", url.Cache.GetClientSocket(clientID))
}

func (url *URL) SignatureToNewSatellite(newSatelliteID string) string {
	return fmt.Sprintf("http://%s/auth/prehandover/sig", url.Cache.GetSatelliteSocket(newSatelliteID))
}
