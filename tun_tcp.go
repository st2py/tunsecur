package main

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// send KeySeed
func TcpKeySend(conn *net.TCPConn, cfg *TunCfg) (s1, s2 cipher.Stream, err error) {
	var seed *KeySeed
	seed, s1, s2, err = GenAesKey(nil, cfg)
	if err != nil {
		return nil, nil, err
	}

	kk := KeySeed2Bytes(seed)
	if kk == nil {
		return nil, nil, errors.New("KeySeed2Bytes failed")
	}
	LogInfo(g_cfg, "SZ: ", len(kk))
	LogInfo(g_cfg, "KK: ", kk)

	if cfg.passWord != "" || cfg.rsaFile != "" {
		kk, err = EncDecKey(kk, cfg)
		if err != nil {
			return nil, nil, err
		}
	}

	if _, err := conn.Write(kk); err != nil {
		return nil, nil, err
	}

	return s1, s2, nil
}

// recv KeySeed
func TcpKeyRecv(conn *net.TCPConn, cfg *TunCfg) (s1, s2 cipher.Stream, err error) {
	var sz int
	if cfg.passWord != "" {
		sz = binary.Size(KeySeed{})
	} else {
		sz, err = RsaPrivateSize(cfg.rsaFile)
		if err != nil {
			return nil, nil, err
		}
	}

	kk := make([]byte, sz)

	if _, err = conn.Read(kk); err != nil {
		return nil, nil, err
	}

	if cfg.passWord != "" || cfg.rsaFile != "" {
		kk, err = EncDecKey(kk, cfg)
		if err != nil {
			return nil, nil, err
		}
	}
	LogInfo(g_cfg, "SZ: ", len(kk))
	LogInfo(g_cfg, "KK: ", kk)

	seed := Bytes2KeySeed(kk)
	if seed == nil {
		return nil, nil, errors.New("Bytes2KeySeed failed")
	} else if seed.Flag != TUN_FLG {
		return nil, nil, errors.New("TUN_FLG check failed")
	}

	_, s1, s2, err = GenAesKey(seed, cfg)
	if err != nil {
		return nil, nil, err
	}

	return s1, s2, nil
}

// flag 1 - encrypt, 2 - decrypt
func TcpPipe(source, dest *net.TCPConn, stream cipher.Stream, flag int) {
	defer dest.CloseWrite()
	defer source.CloseRead()

	if flag == 1 {
		writer := &cipher.StreamWriter{S: stream, W: dest}
		io.Copy(writer, source)
	} else {
		reader := &cipher.StreamReader{S: stream, R: source}
		// Copy the input file to the output file, decrypting as we go.
		io.Copy(dest, reader)
	}
}

func TcpClient(lc *net.TCPConn, cfg *TunCfg) error {
	defer lc.Close()

	conn, err := net.Dial("tcp4", cfg.remoteHost)
	if err != nil {
		LogWarn(g_cfg, err.Error())
		return err
	}

	rc := conn.(*net.TCPConn)

	if cfg.tunFlag { // Tun server
		s1, s2, err := TcpKeyRecv(lc, cfg)
		if err != nil {
			LogWarn(g_cfg, err.Error())
			return err
		}

		go TcpPipe(lc, rc, s1, 2)
		TcpPipe(rc, lc, s2, 1)
	} else { // Tun Client
		s1, s2, err := TcpKeySend(rc, cfg)
		if err != nil {
			LogWarn(g_cfg, err.Error())
			return err
		}

		go TcpPipe(lc, rc, s1, 1)
		TcpPipe(rc, lc, s2, 2)
	}

	return nil
}

func TcpServer(cfg *TunCfg) error {
	LogInfo(g_cfg, "listenHost: ", cfg.listenHost)
	LogInfo(g_cfg, "remoteHost: ", cfg.remoteHost)
	LogInfo(g_cfg, "passWord: ", cfg.passWord)
	LogInfo(g_cfg, "rsaFile: ", cfg.rsaFile)
	LogInfo(g_cfg, "tunFlag: ", cfg.tunFlag)

	// Listen on TCP
	l, err := net.Listen("tcp4", cfg.listenHost)
	if err != nil {
		LogFatal(g_cfg, err.Error())
	}
	defer l.Close()

	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			LogWarn(g_cfg, err.Error())
			continue
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go TcpClient(conn.(*net.TCPConn), cfg)

	}
}
