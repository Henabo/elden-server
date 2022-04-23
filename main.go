package main

import "github.com/hiro942/elden-server/initialize"

func main() {
	//port := *flag.String("p", "20000", "application running port")
	//flag.Parse()
	//fmt.Println("running port:", port)
	//
	//r := router.Routers()
	//r.Run(":" + port)

	initialize.MockInit()
	initialize.SysInit()

}

type A struct {
	Name string
	Age  int
}
