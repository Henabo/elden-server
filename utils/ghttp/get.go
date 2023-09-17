package ghttp

import (
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/pkg/errors"
	"io"
	"net/http"
)

func GET[T any](url string) (res T, err error) {
	rsp, err := http.Get(url)
	if err != nil {
		return res, err
	}
	defer rsp.Body.Close()

	rspBodyBytes, err := io.ReadAll(rsp.Body)
	if err != nil {
		return res, err
	}

	rspBody := utils.JsonUnmarshal[response.Response[T]](rspBodyBytes)
	if rspBody.Code != response.Success {
		return res, errors.Errorf("message: %s, decription: %s", rspBody.Message, rspBody.Description)
	}

	return rspBody.Data, nil
}
