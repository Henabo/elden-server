package response

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type Response[T any] struct {
	Code        int    `json:"code"`
	Data        T      `json:"data"`
	Message     string `json:"message"`
	Description string `json:"description"`
}

const (
	Success = 0
	Error   = 7
)

func Result(code int, data any, message string, description string, c *gin.Context) {
	c.JSON(http.StatusOK, Response{
		code,
		data,
		message,
		description,
	})
}

func OK(c *gin.Context) {
	Result(Success, nil, "successful", "", c)
}

func OKWithMessage(message string, c *gin.Context) {
	Result(Success, nil, message, "", c)
}

func OKWithData(data any, message string, c *gin.Context) {
	Result(Success, data, "success", "", c)
}

func FailWithDescription(message string, description string, c *gin.Context) {
	Result(Error, nil, message, description, c)
}
