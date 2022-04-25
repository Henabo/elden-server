package gxios

import (
	"fmt"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/pkg/errors"
)

func QueryUserPublicKey(id string, macAddr string) (keyHex string, err error) {
	url := fmt.Sprintf("%s/node/user/publicKey?id=%s&macAddr=%s",
		global.FabricAppBaseUrl, id, macAddr)
	resBytes := GET(url)
	res := utils.JsonUnmarshal[response.Response[string]](resBytes)
	if res.Code != 0 {
		return "", errors.Errorf("message: %s, decription: %s", res.Message, res.Description)
	}
	return res.Data, nil
}

func QuerySatellitePublicKey(id string) (keyHex string, err error) {
	url := fmt.Sprintf("%s/node/satellite/publicKey?id=%s", global.FabricAppBaseUrl, id)
	resBytes := GET(url)
	res := utils.JsonUnmarshal[response.Response[string]](resBytes)
	if res.Code != 0 {
		return "", errors.Errorf("message: %s, decription: %s", res.Message, res.Description)
	}
	return res.Data, nil
}

func QueryNodeById(id string) (model.Node, error) {
	url := fmt.Sprintf("%s/node/search?id=%s",
		global.FabricAppBaseUrl, id)
	resBytes := GET(url)
	res := utils.JsonUnmarshal[response.Response[model.Node]](resBytes)
	if res.Code != 0 {
		return model.Node{}, errors.Errorf("message: %s, decription: %s", res.Message, res.Description)
	}
	return res.Data, nil
}

func ChangeUserAuthStatus(id string, authStatusCode string) error {
	resBytes := POST(
		fmt.Sprintf("%s/node/user/changeAuthStatus", global.FabricAppBaseUrl),
		request.ChangeUserAuthStatus{Id: id, AuthStatusCode: authStatusCode},
	)
	if res := utils.JsonUnmarshal[response.Response[any]](resBytes); res.Code != 0 {
		return errors.Errorf("message: %s, decription: %s", res.Message, res.Description)
	}
	return nil
}
