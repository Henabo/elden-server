package main

import (
	"crypto/rand"
	"github.com/hiro942/elden-server/config"
	"log"
	"math/big"
	"time"
)

func main() {
	// 读取配置
	config.LoadConfig()

	// 实例初始化
	cache := NewCache()
	url := NewURL(cache)
	ledger := NewLedger(url)
	satellite := NewSatellite(config.Conf.SatelliteID, cache, ledger)
	session := NewSessions(satellite)
	auth := NewAuthentication(session)

	go auth.Routers().Run(":" + config.Conf.HttpServerPort) // 启动路由

	go auth.PositionUpdater()

	select {}
}

const (
	PositionUpdateFrequency      = 3 // 坐标更新频率，单位:秒
	PositionUpdateVelocityClient = 5
)

func (auth *Authentication) PositionUpdater() {
	satelliteCount := len(auth.SessionPool.Satellite.Cache.SatelliteSockets)

	// 更新坐标
	for range time.Tick(time.Second * PositionUpdateFrequency) {
		for _, session := range auth.SessionPool.SessionMap {
			if session.ClientPosition == 0 {
				// 初始化 client 位置
				session.ClientPosition = RandInt64(config.Conf.ServiceRangeLeft, config.Conf.ServiceRangeRight)
			} else {
				session.ClientPosition += PositionUpdateVelocityClient
				if session.ClientPosition > int64(satelliteCount*100) {
					session.ClientPosition -= int64(satelliteCount * 100)
				}
			}
			log.Printf("【定位服务】客户端「%s」此刻的位置：%d。\n", session.ClientID, session.ClientPosition)
			if session.ClientPosition > config.Conf.ServiceRangeRight || session.ClientPosition < config.Conf.ServiceRangeLeft {
				log.Printf("【切换信号】理想通信位置区间为[%d ,%d]，客户端「%s」当前位置为: %d。可能无法提供平滑通信，开启切换认证流程。\n",
					config.Conf.ServiceRangeLeft, config.Conf.ServiceRangeRight, session.ClientID, session.ClientPosition)
				err := auth.PreHandover(session.ClientID)
				if err != nil {
					log.Printf("【交接认证】切换失败: %+v。\n", err)
				}
				// 移出当前会话集合
				delete(auth.SessionPool.SessionMap, session.ClientID)
			}
		}
	}
}

func RandInt64(min, max int64) int64 {

	maxBigInt := big.NewInt(max)

	i, _ := rand.Int(rand.Reader, maxBigInt)

	if i.Int64() < min {

		RandInt64(min, max)

	}

	return i.Int64()

}
