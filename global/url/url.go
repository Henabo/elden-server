/*
	HTTP请求地址
*/

package url

import (
	"fmt"
	"github.com/hiro942/elden-server/global"
)

const (
	ChangeUserAuthStatus = global.FabricAppBaseUrl + "/node/user/changeAuthStatus"
	CreateAccessRecord   = global.FabricAppBaseUrl + "/node/user/accessRecord"
)

func QueryUserPublicKey(id string, macAddr string) string {
	return global.FabricAppBaseUrl + fmt.Sprintf("/node/user/publicKey?id=%s&macAddr=%s", id, macAddr)
}

func QuerySatellitePublicKey(id string) string {
	return global.FabricAppBaseUrl + fmt.Sprintf("/node/satellite/publicKey?id=%s", id)
}

func QueryNodeById(id string) string {
	return global.FabricAppBaseUrl + fmt.Sprintf("/node/search?id=%s", id)
}

func NewSatelliteIdToUser(userId string, newSatelliteId string) string {
	return fmt.Sprintf("http://%s/auth/prehandover/new_satellite?id=%s", global.CurrentSessions[userId].Socket, newSatelliteId)
}

func RequestForUserLocation(id string) string {
	return fmt.Sprintf("http://%s/auth/prehandover/location", global.CurrentSessions[id].Socket)
}

func SignatureToNewSatellite(newSatelliteId string) string {
	return fmt.Sprintf("http://%s/auth/prehandover/sig", global.SatelliteSockets[newSatelliteId])
}
