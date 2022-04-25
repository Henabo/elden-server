package initialize

import "github.com/hiro942/elden-server/global"

func MockInit() {
	global.MockUserId = "hashed-9"
	global.MySatelliteId = "satellite-99"
	global.MockNewSatelliteId = "satellite-999"
	global.SatelliteSocket[global.MySatelliteId] = "localhost:20000"
	global.SatelliteSocket[global.MockNewSatelliteId] = "localhost:20001"

}
