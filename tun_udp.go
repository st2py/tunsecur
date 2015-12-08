package main

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

const BUF_LEN = 10000

type UdpChn struct {
	addr *net.UDPAddr
	buf  *bytes.Buffer
	lc   *net.UDPConn
	rc   *net.UDPConn
	cfg  *TunCfg
	s1   *cipher.Stream
	s2   *cipher.Stream
	flg  int
	evt  chan int
	err  chan int
}

// send aes-128-ctr key and iv
func ChnKeySend(chn *UdpChn) error {
	conn := chn.rc
	cfg := chn.cfg

	var seed *KeySeed
	var s1, s2 cipher.Stream
	var err error
	seed, s1, s2, err = GenAesKey(nil, cfg)
	if err != nil {
		return err
	}

	kk := KeySeed2Bytes(seed)
	if kk == nil {
		return errors.New("KeyMsg2Bytes failed")
	}
	LogInfo(cfg, "SZ: ", len(kk))
	LogInfo(cfg, "KK: ", kk)

	if cfg.passWord != "" || cfg.rsaFile != "" {
		kk, err = EncDecKey(kk, cfg)
		if err != nil {
			return err
		}
	}

	if _, err := conn.Write(kk); err != nil {
		return err
	}
	chn.s1 = &s1
	chn.s2 = &s2

	return nil
}

// recv aes-128-ctr key and iv
func ChnKeyRecv(chn *UdpChn) error {
	cfg := chn.cfg
	var sz int
	var err error
	if cfg.passWord != "" {
		sz = binary.Size(KeySeed{})
	} else {
		sz, err = RsaPrivateSize(cfg.rsaFile)
		if err != nil {
			return err
		}
	}

	if chn.buf.Len() < sz {
		return errors.New("ChnKeyRecv len failed")
	}

	kk := make([]byte, sz)
	nn, err := chn.buf.Read(kk)
	if err != nil {
		return err
	} else if nn != sz {
		return errors.New("ChnKeyRecv read failed")
	}

	if cfg.passWord != "" || cfg.rsaFile != "" {
		kk, err = EncDecKey(kk, cfg)
		if err != nil {
			return err
		}
	}
	LogInfo(cfg, "SZ: ", len(kk))
	LogInfo(cfg, "KK: ", kk)

	seed := Bytes2KeySeed(kk)
	if seed == nil {
		return errors.New("Bytes2KeySeed failed")
	} else if seed.Flag != TUN_FLG {
		return errors.New("TUN_FLG check failed")
	}

	var s1, s2 cipher.Stream
	_, s1, s2, err = GenAesKey(seed, cfg)
	if err != nil {
		return err
	}

	chn.s1 = &s1
	chn.s2 = &s2
	return nil
}

// flag 1 - encrypt, 2 - decrypt
func Lc2RcPipe(source *UdpChn, dest *net.UDPConn, s *cipher.Stream, flag int) {
	var nn int64
	var err error
	slen := source.buf.Len()
	if flag == 1 {
		writer := &cipher.StreamWriter{S: *s, W: dest}
		nn, err = io.Copy(writer, source.buf)
	} else {
		reader := &cipher.StreamReader{S: *s, R: source.buf}
		nn, err = io.Copy(dest, reader)
	}

	if err != nil {
		LogWarn(g_cfg, "Lc2RcPipe:", err.Error())
	} else if nn != int64(slen) {
		LogWarn(g_cfg, "Lc2RcPipe: io.Copy failed")
	}

	//	nn, _ := io.Copy(dest, source.buf)
	LogInfo(g_cfg, "Lc2RcPipe:", source.addr.String(), ", ", nn)
}

// flag 1 - encrypt, 2 - decrypt
func Rc2LcPipe(source *net.UDPConn, dest *UdpChn, s *cipher.Stream, flag int) {
	buf := make([]byte, BUF_LEN)
	source.SetDeadline(time.Now().Add(time.Second * 15))
	nn, _, err := source.ReadFromUDP(buf)
	if err != nil {
		LogWarn(g_cfg, "Rc2LcPipe:", err.Error())
		return
	}
	LogInfo(g_cfg, "Rc2LcPipe:", dest.addr.String(), ", ", nn)
	//	dest.lc.WriteToUDP(buf[:nn], dest.addr)

	var mm int64
	wrt := new(bytes.Buffer)
	if flag == 1 {
		writer := &cipher.StreamWriter{S: *s, W: wrt}
		mm, _ = io.Copy(writer, bytes.NewReader(buf[:nn]))
	} else {
		reader := &cipher.StreamReader{S: *s, R: bytes.NewReader(buf[:nn])}
		mm, _ = io.Copy(wrt, reader)
	}

	if int64(nn) != mm {
		LogWarn(g_cfg, "Rc2LcPipe: cipher error", nn, mm)
		return
	}
	dest.lc.WriteToUDP(wrt.Bytes(), dest.addr)
}

func HandleChn(chn *UdpChn) error {
	if chn.flg == 0 {
		chn.flg = 1

		rt, err := net.Dial("udp4", chn.cfg.remoteHost)
		if err != nil {
			return err
		}
		chn.rc = rt.(*net.UDPConn)

		if chn.cfg.tunFlag {
			err := ChnKeyRecv(chn)
			if err != nil {
				return err
			}
		} else {
			err := ChnKeySend(chn)
			if err != nil {
				return err
			}
		}
	}

	if chn.cfg.tunFlag {
		go Rc2LcPipe(chn.rc, chn, chn.s2, 1)
		Lc2RcPipe(chn, chn.rc, chn.s1, 2)
	} else {
		go Rc2LcPipe(chn.rc, chn, chn.s2, 2)
		Lc2RcPipe(chn, chn.rc, chn.s1, 1)
	}

	return nil
}

func ChnLoop(tbl *map[string]*UdpChn, chn *UdpChn) {
	str := chn.addr.String()
	for {
		select {
		case <-chn.evt:
			if chn.buf.Len() == 0 {
				LogWarn(g_cfg, "ChnLoop buf zero")
				continue
			}
			err := HandleChn(chn)
			if err != nil {
				LogWarn(g_cfg, err.Error())
				chn.err <- 1
			}

		case <-chn.err:
			LogWarn(g_cfg, "ChnLoop error")
			if chn.rc != nil {
				chn.rc.Close()
			}
			delete(*tbl, str)
			return

		case <-time.After(time.Second * 30):
			LogWarn(g_cfg, "ChnLoop timeout")
			if chn.rc != nil {
				chn.rc.Close()
			}
			delete(*tbl, str)
			return
		}
	}
}

func Send2Chn(chn *UdpChn, buf []byte, len int) error {
	wn, err := chn.buf.Write(buf)
	if err != nil {
		chn.err <- 1
		return err
	} else if wn != len {
		chn.err <- 1
		return errors.New("Send2Chn failed")
	}
	chn.evt <- 1
	return nil
}

func UdpServer(cfg *TunCfg) error {
	LogInfo(cfg, "listenHost:", cfg.listenHost)
	LogInfo(cfg, "remoteHost:", cfg.remoteHost)
	LogInfo(cfg, "passWord:", cfg.passWord)
	LogInfo(cfg, "rsaFile:", cfg.rsaFile)
	LogInfo(cfg, "tunFlag:", cfg.tunFlag)

	addr, err := net.ResolveUDPAddr("udp4", cfg.listenHost)
	if err != nil {
		LogFatal(cfg, err.Error())
	}

	// Listen on UDP
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		LogFatal(cfg, err.Error())
	}
	defer conn.Close()
	LogInfo(cfg, "Local:", conn.LocalAddr())

	buf := make([]byte, BUF_LEN)
	tbl := make(map[string]*UdpChn)
	for {
		nnn, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			LogWarn(cfg, err.Error())
			continue
		}
		LogInfo(cfg, "Chn Read:", nnn)

		str := addr.String()
		LogInfo(cfg, "Addr:", str)
		chn, ok := tbl[str]
		if !ok {
			chn = &UdpChn{addr, new(bytes.Buffer), conn, nil, cfg, nil, nil,
				0, make(chan int, 7), make(chan int, 7)}
			tbl[str] = chn
			go ChnLoop(&tbl, chn)
		}

		err = Send2Chn(chn, buf[:nnn], nnn)
		if err != nil {
			LogWarn(cfg, err.Error())
			continue
		}
	}
}
