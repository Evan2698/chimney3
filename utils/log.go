package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"
)

type highspeeddevice struct {
}

func (high *highspeeddevice) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func setHighSpeed() io.Writer {
	return &highspeeddevice{}
}

func setlogglobal() io.Writer {
	t := time.Now()
	timestamp := strconv.FormatInt(t.UTC().UnixNano(), 10)
	var logpath = "log_" + timestamp + ".txt"
	var file io.Writer
	var err1 error
	file, err1 = os.Create(logpath)
	if err1 != nil {
		fmt.Print("can not create log file", err1)
		file = &highspeeddevice{}
	}
	return io.MultiWriter(os.Stdout, file)
}

func init() {
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Llongfile)
	log.SetOutput(setHighSpeed())
}
