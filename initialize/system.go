package initialize

import (
	"fmt"
	"github.com/hiro942/elden-server/global"
	"github.com/hiro942/elden-server/mock"
	"github.com/hiro942/elden-server/router"
	"github.com/hiro942/elden-server/service"
	"github.com/hiro942/elden-server/utils"
	"log"
	"time"
)

func SysInit() {
	// 读取公私钥、或生成公私钥并将公钥注册上链
	if !utils.FileExist(global.PrivateKeyPath) || !utils.FileExist(global.PublicKeyPath) {
		if err := service.Register(); err != nil {
			log.Panicln(fmt.Errorf("register error: %v", err))
		}
	} else {
		utils.ReadKeyPair()
	}

	go router.Routers().Run(":" + global.DefaultAuthenticationPort) // 启动路由

	// 【模拟】不停判断是否已经和用户完成了 Normal Access，接入后等3秒开始给用户发送预切换请求
	for {
		session, ok := global.CurrentSessions[mock.UserId]
		if ok && session.AccessType == global.NormalAccess {
			log.Println("Keep Session (normal access) For 3 seconds ...")
			time.Sleep(time.Second * 90)
			if err := service.PreHandover(mock.UserId); err != nil {
				log.Panicln(fmt.Errorf("first access error: %+v", err))
			}
			break
		}

		time.Sleep(time.Microsecond * 500)
	}

	for {
	}
}
