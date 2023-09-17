package ghttp

import (
	"bytes"
	"github.com/hiro942/elden-server/model/response"
	"github.com/hiro942/elden-server/utils"
	"github.com/pkg/errors"
	"io"
	"net/http"
)

func POST[T any](url string, reqBody any) (res T, err error) {
	reqBodyBytes := utils.JsonMarshal(reqBody)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(reqBodyBytes))
	if err != nil {
		return res, err
	}

	req.Header.Set("Content-Type", "application/json")

	rsp, err := http.DefaultClient.Do(req)
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
