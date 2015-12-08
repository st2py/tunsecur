package main

import (
	"bytes"
	"flag"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const TUN_FLG = 0x23571719

type TunCfg struct {
	listenHost string
	remoteHost string
	passWord   string
	rsaFile    string
	dtlLogs    int
	tunFlag    bool // false for tun client, true for tun server
	aesType    int  // ctr - 1, cfb - 2, ofb - 4
	aesBits    int  // 16, 24, 32

	nBuf    bytes.Buffer
	wBuf    bytes.Buffer
	eBuf    bytes.Buffer
	nLogger *log.Logger
	wLogger *log.Logger
	eLogger *log.Logger
}

var g_cfg *TunCfg

func main() {
	var genKey bool
	flag.BoolVar(&genKey, "gen", false, "Generate RSA key files")
	var bits int
	flag.IntVar(&bits, "bit", 2048, "RSA key length, only valid: 1024, 2048, 4096")
	var keyPath string
	flag.StringVar(&keyPath, "dir", "", "RSA key files directory path")

	var dtl int
	flag.IntVar(&dtl, "log", 1, "Log bits, error 1, warn 2, info 4")

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

	var aesType string
	flag.StringVar(&aesType, "aes", "ctr", "AES type, only valid: ctr, cfb, ofb")
	var aesBits int
	flag.IntVar(&aesBits, "len", 16, "AES key len, only valid: 16, 24, 32")

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

	if cfg.dtlLogs < 0 {
		cfg.dtlLogs = 1
	} else if cfg.dtlLogs > 7 {
		cfg.dtlLogs = 7
	}

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
			LogFatal(cfg, "-remote missing for -tc or -ts")
		}

		if aesType != "ctr" && aesType != "cfb" && aesType != "ofb" {
			LogFatal(cfg, "-aes invalid, only valid: ctr, cfb, ofb")
		}

		if aesBits != 16 && aesBits != 24 && aesBits != 32 {
			LogFatal(cfg, "-len invalid, only valid: 16, 24, 32")
		}

		if !tcp && !udp {
			LogFatal(cfg, "-tcp or -udp missing for -tc or -ts")
		}

		if tc && passWord == "" && pubFile == "" {
			LogFatal(cfg, "-passwd or -pub missing for -tc")
		}

		if ts && passWord == "" && privFile == "" {
			LogFatal(cfg, "-passwd or -priv missing for -ts")
		}
	}

	if genKey == true {
		if bits != 1024 && bits != 2048 && bits != 4096 && bits != 8192 {
			LogFatal(cfg, "-bit invalid, only valid: 1024, 2048, 4096")
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
		cfg.aesBits = aesBits
		switch aesType {
		case "ctr":
			cfg.aesType = 1
		case "cfb":
			cfg.aesType = 2
		case "ofb":
			cfg.aesType = 4
		}

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
