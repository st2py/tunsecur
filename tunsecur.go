package main

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func main() {
	var genKey bool
	flag.BoolVar(&genKey, "g", false, "Generate RSA key files")
	var bits int
	flag.IntVar(&bits, "b", 2048, "RSA key length, only valid for 1024, 2048, 4096")
	var keyPath string
	flag.StringVar(&keyPath, "p", "", "RSA key files directory path")

	var dtl int
	flag.IntVar(&dtl, "d", 1, "Logs, 1 for error, 2 for warn, 4 for info")

	var tc bool
	flag.BoolVar(&tc, "c", false, "Tunnel client")
	var listenHost string
	flag.StringVar(&listenHost, "l", "0.0.0.0:3257", "Listen port")

	var ts bool
	flag.BoolVar(&ts, "s", false, "Tunnel server")
	var remoteHost string
	flag.StringVar(&remoteHost, "r", "", "Remote host and port")
	var passWord string
	flag.StringVar(&passWord, "W", "", "Tunnel password")
	var pubFile string
	flag.StringVar(&pubFile, "P", "", "RSA public key file")
	var privFile string
	flag.StringVar(&privFile, "S", "", "RSA secret key file")

	var tcp bool
	flag.BoolVar(&tcp, "T", false, "TCP Tunnel")
	var udp bool
	flag.BoolVar(&udp, "U", false, "UDP Tunnel")

	flag.Parse()

	cfg := new(TunCfg)
	g_cfg = cfg
	cfg.listenHost = listenHost
	cfg.remoteHost = remoteHost
	cfg.passWord = passWord
	cfg.dtlLogs = dtl
	LogInit(cfg)

	relFile, _ := exec.LookPath(os.Args[0])
	selfName := filepath.Base(relFile)
	absFile, _ := filepath.Abs(relFile)
	absPath, _ := filepath.Abs(filepath.Dir(absFile))

	LogInfo(cfg, "Program:", selfName)
	LogInfo(cfg, "AbsPath:", absPath)
	LogInfo(cfg, "CpuNums:", runtime.NumCPU())

	runtime.GOMAXPROCS(runtime.NumCPU() * 2)

	if tc || ts {
		if remoteHost == "" {
			LogFatal(cfg, "-r must be set")
		}

		if !tcp && !udp {
			LogFatal(cfg, "-T or -U must be set")
		}

		if tc && passWord == "" && pubFile == "" {
			LogFatal(cfg, "-W or -P must be set for tunnel client")
		}

		if ts && passWord == "" && privFile == "" {
			LogFatal(cfg, "-W or -S must be set for tunnel server")
		}
	}

	if genKey == true {
		if bits != 1024 && bits != 2048 && bits != 4096 && bits != 8192 {
			LogFatal(cfg, "Error: -b only valid for 1024 2048 4096")
		}

		if keyPath == "" {
			keyPath = filepath.Join(absPath, "keys")
		} else {
			if !IsDirExist(keyPath) {
				LogFatal(cfg, "Error: path ", keyPath, " isn't exist")
			}
		}

		LogInfo(cfg, "RSA key length", bits)
		LogInfo(cfg, "Directory at", keyPath)
		err := RsaGenKey(keyPath, bits)
		if err != nil {
			LogInfo(cfg, err.Error())
			LogFatal(cfg, "Error: generate RSA key failed")
		}
		LogInfo(cfg, "Generate RSA key OK")
		LogWarn(cfg, "Please backup your RSA key files carefully")
	} else if tc || ts {
		if tc {
			cfg.rsaFile = pubFile
			cfg.tunFlag = false
		} else {
			cfg.rsaFile = privFile
			cfg.tunFlag = true
		}

		if tcp {
			TcpServer(cfg)
		} else {
			UdpServer(cfg)
		}

	} else {
		flag.PrintDefaults()
	}

}
