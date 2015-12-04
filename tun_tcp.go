package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
)

const AES_LEN = 16
const TUN_FLG = 0x23571719

type TunCfg struct {
	listenHost string
	remoteHost string
	passWord   string
	rsaFile    string
	dtlLogs    int
	tunFlag    bool // false for tun client, true for tun server

	nBuf    bytes.Buffer
	wBuf    bytes.Buffer
	eBuf    bytes.Buffer
	nLogger *log.Logger
	wLogger *log.Logger
	eLogger *log.Logger
}

var g_cfg *TunCfg

// 96 bytes
type KeyMsg struct {
	R1   [12]byte // random for security
	Flag uint32   // TUN_FLG
	K1   [AES_LEN]byte
	V1   [aes.BlockSize]byte
	K2   [AES_LEN]byte
	V2   [aes.BlockSize]byte
	R2   [16]byte // random for security
}

func KeyMsg2Bytes(msg *KeyMsg) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, msg)
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

func Bytes2KeyMsg(b []byte) *KeyMsg {
	msg := new(KeyMsg)
	buf := bytes.NewReader(b)
	err := binary.Read(buf, binary.LittleEndian, msg)
	if err != nil {
		return nil
	}
	return msg
}

func AesEncDec(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

func GenAesKey() (*KeyMsg, error) {
	msg := new(KeyMsg)
	msg.Flag = TUN_FLG
	if _, err := io.ReadFull(rand.Reader, msg.R1[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, msg.R2[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, msg.K1[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, msg.V1[:]); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(rand.Reader, msg.K2[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, msg.V2[:]); err != nil {
		return nil, err
	}

	return msg, nil
}

func RsaEncKey(kk []byte, cfg *TunCfg) ([]byte, error) {
	publicKey := RsaReadKey(cfg.rsaFile)
	if publicKey == nil {
		return nil, errors.New("RsaReadKey failed")
	}

	k1, err := RsaEncrypt(publicKey, kk)
	if err != nil {
		return nil, err
	}

	return k1, nil
}

func RsaDecKey(kk []byte, cfg *TunCfg) ([]byte, error) {
	privateKey := RsaReadKey(cfg.rsaFile)
	if privateKey == nil {
		return nil, errors.New("RsaReadKey failed")
	}

	k1, err := RsaDecrypt(privateKey, kk)
	if err != nil {
		return nil, err
	}

	return k1, nil
}

func EncDecKey(kk []byte, cfg *TunCfg) ([]byte, error) {
	if cfg.passWord != "" {
		h1 := sha256.New()
		io.WriteString(h1, "St2Py")
		io.WriteString(h1, cfg.passWord)
		io.WriteString(h1, "TunSecur")
		key := h1.Sum(nil)

		h1 = sha256.New()
		io.WriteString(h1, "St2Py")
		io.WriteString(h1, cfg.passWord)
		io.WriteString(h1, "TunSecur")
		ivt := h1.Sum(key)

		k1, err := AesEncDec(kk, key[:16], ivt[:aes.BlockSize])
		if err != nil {
			return nil, err
		}

		return k1, nil
	} else {
		if cfg.tunFlag {
			return RsaDecKey(kk, cfg)
		} else {
			return RsaEncKey(kk, cfg)
		}
	}
}

// send aes-128-ctr key and iv
func TcpKeySend(conn *net.TCPConn, cfg *TunCfg) (s1, s2 cipher.Stream, err error) {
	msg, err := GenAesKey()
	if err != nil {
		return nil, nil, err
	}
	b1, err := aes.NewCipher(msg.K1[:])
	if err != nil {
		return nil, nil, err
	}
	s1 = cipher.NewCTR(b1, msg.V1[:])
	//	log.Println("SKey:", msg.K1)
	//	log.Println("SIVT:", msg.V1)

	b2, err := aes.NewCipher(msg.K2[:])
	if err != nil {
		return nil, nil, err
	}
	s2 = cipher.NewCTR(b2, msg.V2[:])
	//	log.Println("RKey:", msg.K2)
	//	log.Println("RIVT:", msg.V2)

	kk := KeyMsg2Bytes(msg)
	if kk == nil {
		return nil, nil, errors.New("KeyMsg2Bytes failed")
	}
	log.Println("SZ:", len(kk))
	log.Println("KK:", kk)

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

// recv aes-128-ctr key and iv
func TcpKeyRecv(conn *net.TCPConn, cfg *TunCfg) (s1, s2 cipher.Stream, err error) {
	var sz int
	if cfg.passWord != "" {
		sz = binary.Size(KeyMsg{})
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
	log.Println("SZ:", len(kk))
	log.Println("KK:", kk)

	msg := Bytes2KeyMsg(kk)
	if msg == nil {
		return nil, nil, errors.New("Bytes2KeyMsg failed")
	} else if msg.Flag != TUN_FLG {
		return nil, nil, errors.New("TUN_FLG check failed")
	}

	b1, err := aes.NewCipher(msg.K1[:])
	if err != nil {
		return nil, nil, err
	}
	s1 = cipher.NewCTR(b1, msg.V1[:])
	//	log.Println("SKey:", msg.K1)
	//	log.Println("SIVT:", msg.V1)

	b2, err := aes.NewCipher(msg.K2[:])
	if err != nil {
		return nil, nil, err
	}
	s2 = cipher.NewCTR(b2, msg.V2[:])
	//	log.Println("RKey:", msg.K2)
	//	log.Println("RIVT:", msg.V2)

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
		log.Println(err)
		return err
	}

	rc := conn.(*net.TCPConn)

	if cfg.tunFlag { // Tun server
		s1, s2, err := TcpKeyRecv(lc, cfg)
		if err != nil {
			log.Println(err)
			return err
		}

		go TcpPipe(lc, rc, s1, 2)
		TcpPipe(rc, lc, s2, 1)
	} else { // Tun Client
		s1, s2, err := TcpKeySend(rc, cfg)
		if err != nil {
			log.Println(err)
			return err
		}

		go TcpPipe(lc, rc, s1, 1)
		TcpPipe(rc, lc, s2, 2)
	}

	return nil
}

func TcpServer(cfg *TunCfg) error {
	log.Println("listenHost:", cfg.listenHost)
	log.Println("remoteHost:", cfg.remoteHost)
	log.Println("passWord:", cfg.passWord)
	log.Println("rsaFile:", cfg.rsaFile)
	log.Println("tunFlag:", cfg.tunFlag)

	// Listen on TCP
	l, err := net.Listen("tcp4", cfg.listenHost)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go TcpClient(conn.(*net.TCPConn), cfg)

	}
}
