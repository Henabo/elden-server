package utils

import (
	"fmt"
	"github.com/hiro942/elden-server/constant"
	"log"
	"os"
)

func FileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

func WriteFile(path string, data []byte) {
	err := os.WriteFile(path, data, constant.DefaultFilePerm)
	if err != nil {
		log.Panicln(fmt.Printf("failed to write file: %+v", err))
	}
}

func ReadFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Panicln(fmt.Printf("failed to read file: %+v", err))
	}
	return data
}
