package initialize

import (
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/mock"
)

func MockInit() {
	mock.UserId = "hashed-UUU"
	global.MySatelliteId = "satellite-AAA"
	mock.NewSatelliteId = "satellite-BBB"
	global.UserSockets[mock.UserId] = "localhost:19999"
	global.SatelliteSockets[global.MySatelliteId] = "localhost:20000"
	global.SatelliteSockets[mock.NewSatelliteId] = "localhost:20001"
}
