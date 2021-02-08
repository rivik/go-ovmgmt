package ovmgmt

import (
	"io/ioutil"
	"log"
)

var pkgLogger *log.Logger = nil

func SetLogger(logger *log.Logger) {
	pkgLogger = logger
}

func logErrorf(f string, v ...interface{}) {
	pkgLogger.Printf("ERROR:\t"+f, v...)
}

func init() {
	pkgLogger = log.New(ioutil.Discard, "", 0)
}
