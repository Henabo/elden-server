package router

import (
	"github.com/gin-gonic/gin"
	"github.com/hiro942/elden-server/controller"
	"github.com/hiro942/elden-server/middleware"
)

func Routers() *gin.Engine {
	r := gin.Default()
	r.Use(middleware.Cors())

	authGroup := r.Group("auth")
	{
		authGroup.POST("first/step1", controller.FirstAccessStep1)
		authGroup.POST("first/step2", controller.FirstAccessStep2)
		authGroup.POST("normal", controller.NormalAccess)
		authGroup.POST("prehandover", controller.PreHandover)
		authGroup.POST("handover", controller.Handover)
	}

	return r
}
