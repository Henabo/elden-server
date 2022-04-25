package initialize

import (
	"fmt"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/router"
	"github.com/hiro942/elden-server/service"
	"github.com/hiro942/elden-server/utils"
	"log"
	"time"
)

func SysInit() {
	// 读取公私钥，或
	// 生成公私钥，并将公钥注册上链
	if !utils.FileExist(global.PrivateKeyPath) || !utils.FileExist(global.PublicKeyPath) {
		if err := service.Register(); err != nil {
			log.Panicln(fmt.Errorf("register error: %v", err))
		}
	} else {
		utils.ReadKeyPair()
	}

	go router.Routers().Run(":" + global.DefaultAuthenticationPort)
	time.Sleep(time.Second * 30)

	service.PreHandover(global.MockUserId)

	for {
	}
}
