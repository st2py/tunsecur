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
	flag.BoolVar(&genKey, "gen", false, "Generate RSA key files")
	var bits int
	flag.IntVar(&bits, "bit", 2048, "RSA key length, only valid for 1024, 2048, 4096")
	var keyPath string
	flag.StringVar(&keyPath, "dir", "", "RSA key files directory path")

	var dtl int
	flag.IntVar(&dtl, "log", 1, "Log levels, error 1, warn 2, info 4")

	var tc bool
	flag.BoolVar(&tc, "tc", false, "Tunnel client")
	var listenHost string
	flag.StringVar(&listenHost, "lp", "0.0.0.0:19919", "Listen port")

	var ts bool
	flag.BoolVar(&ts, "ts", false, "Tunnel server")
	var remoteHost string
	flag.StringVar(&remoteHost, "remote", "", "Remote host:port")
	var passWord string
	flag.StringVar(&passWord, "passwd", "", "Tunnel password for client and server")
	var pubFile string
	flag.StringVar(&pubFile, "pub", "", "Tunnel client RSA public key file")
	var privFile string
	flag.StringVar(&privFile, "priv", "", "Tunnel server RSA private key file")

	var tcp bool
	flag.BoolVar(&tcp, "tcp", false, "TCP Tunnel")
	var udp bool
	flag.BoolVar(&udp, "udp", false, "UDP Tunnel")

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
			LogFatal(cfg, "missing -remote for -tc or -ts")
		}

		if !tcp && !udp {
			LogFatal(cfg, "missing -tcp or -udp for -tc or -ts")
		}

		if tc && passWord == "" && pubFile == "" {
			LogFatal(cfg, "missing -passwd or -pub for -tc")
		}

		if ts && passWord == "" && privFile == "" {
			LogFatal(cfg, "missing -passwd or -priv for -ts")
		}
	}

	if genKey == true {
		if bits != 1024 && bits != 2048 && bits != 4096 && bits != 8192 {
			LogFatal(cfg, "-bit only valid for 1024 2048 4096")
		}

		if keyPath == "" {
			keyPath = filepath.Join(absPath, "keys")
		} else {
			if !IsDirExist(keyPath) {
				LogFatal(cfg, "path ", keyPath, " isn't exist")
			}
		}

		cfg.dtlLogs |= 7
		LogInfo(cfg, "RSA key length ", bits)
		LogInfo(cfg, "Directory at ", keyPath)
		// cfg.dtlLogs &= ^4
		err := RsaGenKey(keyPath, bits)
		if err != nil {
			LogWarn(cfg, err.Error())
			LogFatal(cfg, "generate RSA key failed")
		}

		// cfg.dtlLogs |= 6
		LogInfo(cfg, "Generate RSA key OK")
		LogWarn(cfg, "Backup your RSA key files!")
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
