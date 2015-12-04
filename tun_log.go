package main

import (
	"fmt"
	"log"
	"os"
)

func LogInit(cfg *TunCfg) {
	cfg.nLogger = log.New(&cfg.nBuf, "[Info]: ", log.LstdFlags)
	cfg.wLogger = log.New(&cfg.wBuf, "[Warn]: ", log.LstdFlags)
	cfg.eLogger = log.New(&cfg.eBuf, "[Error]: ", log.LstdFlags)
}

func LogInfo(cfg *TunCfg, v ...interface{}) {
	if (cfg.dtlLogs & 4) != 0 {
		cfg.nLogger.Print(v...)
		fmt.Print(&cfg.nBuf)
		cfg.nBuf.Reset()
	}
}

func LogWarn(cfg *TunCfg, v ...interface{}) {
	if (cfg.dtlLogs & 2) != 0 {
		cfg.wLogger.Print(v...)
		fmt.Print(&cfg.wBuf)
		cfg.wBuf.Reset()
	}
}

func LogFatal(cfg *TunCfg, v ...interface{}) {
	if (cfg.dtlLogs & 1) != 0 {
		cfg.eLogger.Print(v...)
		fmt.Println(&cfg.eBuf)
		os.Exit(1)
	}
}
