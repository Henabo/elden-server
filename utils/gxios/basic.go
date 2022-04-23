package gxios

import (
	"fmt"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
)

func GetFormatResponse[DataType any](resBytes []byte) response.Response[DataType] {
	res := utils.JsonUnmarshal[response.Response[DataType]](resBytes)
	return res
}

func QueryUserPublicKey(id string, macAddr string) (keyHex string) {
	url := fmt.Sprintf("%s/node/user/publicKey?id=%s&macAddr=%s",
		global.FabricAppBaseUrl, id, macAddr)
	resBytes := GET(url)
	res := GetFormatResponse[string](resBytes)
	return res.Data
}

func QueryNodeById(id string) model.Node {
	url := fmt.Sprintf("%s/node/search?id=%s",
		global.FabricAppBaseUrl, id)
	resBytes := GET(url)
	res := GetFormatResponse[model.Node](resBytes)
	return res.Data
}

func QuerySatellitePublicKey(id string) (keyHex string) {
	url := fmt.Sprintf("%s/node/satellite/publicKey?id=%s", global.FabricAppBaseUrl, id)
	resBytes := GET(url)
	res := GetFormatResponse[string](resBytes)
	return res.Data
}
