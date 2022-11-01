package gxios

import (
	"bytes"
	"github.com/hiro942/elden-server/utils"
	"io"
	"log"
	"net/http"
)

func POST[T any](url string, body T) []byte {
	bodyBytes := utils.JsonMarshal(body)
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		log.Panicln("failed to new request", err)
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		log.Panicln("http error", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Panicln("failed to close http response body")
		}
	}(response.Body)

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Panicln("failed to read response body")
	}

	return responseBytes
}
