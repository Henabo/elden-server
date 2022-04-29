package gxios

import (
	"github.com/hiro942/elden-server/global/url"
	"github.com/hiro942/elden-server/model"
	"github.com/hiro942/elden-server/model/request"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/pkg/errors"
)

func QueryUserPublicKey(id string, macAddr string) (keyHex string, err error) {
	resBytes := GET(url.QueryUserPublicKey(id, macAddr))
	res := utils.JsonUnmarshal[response.Response[string]](resBytes)
	if res.Code != 0 {
		return "", errors.Errorf("message: %s, decription: %s", res.Message, res.Description)
	}
	return res.Data, nil
}

func QuerySatellitePublicKey(id string) (keyHex string, err error) {
	resBytes := GET(url.QuerySatellitePublicKey(id))
	res := utils.JsonUnmarshal[response.Response[string]](resBytes)
	if res.Code != 0 {
		return "", errors.Errorf("message: %s, decription: %s", res.Message, res.Description)
	}
	return res.Data, nil
}

func QueryNodeById(id string) (model.Node, error) {
	resBytes := GET(url.QueryNodeById(id))
	res := utils.JsonUnmarshal[response.Response[model.Node]](resBytes)
	if res.Code != 0 {
		return model.Node{}, errors.Errorf("message: %s, decription: %s", res.Message, res.Description)
	}
	return res.Data, nil
}

func ChangeUserAuthStatus(id string, authStatusCode string) error {
	requestBody := request.ChangeUserAuthStatus{Id: id, AuthStatusCode: authStatusCode}
	resBytes := POST(url.ChangeUserAuthStatus, requestBody)
	if res := utils.JsonUnmarshal[response.Response[any]](resBytes); res.Code != 0 {
		return errors.Errorf("message: %s, decription: %s", res.Message, res.Description)
	}
	return nil
}
