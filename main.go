package main

import (
	"chimney3/all"
	"chimney3/settings"
	"chimney3/utils"
	"flag"
	"fmt"
	"os"
	"runtime"
)

var (
	isServer *bool
)

func main() {

	cpu := runtime.NumCPU()
	runtime.GOMAXPROCS(cpu * 4)

	dir, _ := utils.RetrieveExePath()
	jsonPath := dir + "/setting.json"
	if (len(jsonPath)) == 0 {
		fmt.Println("config file path is incorrect!!", jsonPath)
		os.Exit(1)
	}

	settings, err := settings.Parse(jsonPath)
	if err != nil {
		fmt.Println("load config file failed!", err)
		os.Exit(1)
	}

	isServer = flag.Bool("s", false, "a bool")
	flag.Parse()

	all.Reactor(settings, *isServer)
}
