package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	// "errors"
	"io"
)

const AES_LEN = 32
const SeedLen = 4

// 96 bytes
type KeyMsg struct {
	K1 [AES_LEN]byte
	V1 [aes.BlockSize]byte
	K2 [AES_LEN]byte
	V2 [aes.BlockSize]byte
}

// 48 bytes
type KeySeed struct {
	R1   [12]byte // random for security
	Flag uint32   // TUN_FLG

	K1 [SeedLen]byte
	V1 [SeedLen]byte
	K2 [SeedLen]byte
	V2 [SeedLen]byte

	AesType uint8    // ctr - 1, cfb - 2, ofb - 4
	AesBits uint8    // 16, 24, 32
	R2      [14]byte // random for security

}

func KeySeed2KeyMsg(seed *KeySeed) *KeyMsg {

	h1 := sha256.New()
	io.WriteString(h1, "St2Py")
	io.WriteString(h1, hex.EncodeToString(seed.K1[:]))
	io.WriteString(h1, "TunSecur")
	k1 := h1.Sum(nil)

	h1 = sha256.New()
	io.WriteString(h1, "St2Py")
	io.WriteString(h1, hex.EncodeToString(seed.V1[:]))
	io.WriteString(h1, "TunSecur")
	v1 := h1.Sum(k1)

	h1 = sha256.New()
	io.WriteString(h1, "St2Py")
	io.WriteString(h1, hex.EncodeToString(seed.K2[:]))
	io.WriteString(h1, "TunSecur")
	k2 := h1.Sum(nil)

	h1 = sha256.New()
	io.WriteString(h1, "St2Py")
	io.WriteString(h1, hex.EncodeToString(seed.V2[:]))
	io.WriteString(h1, "TunSecur")
	v2 := h1.Sum(k2)

	msg := new(KeyMsg)
	copy(msg.K1[:], k1[:AES_LEN])
	copy(msg.K2[:], k2[:AES_LEN])
	copy(msg.V1[:], v1[:aes.BlockSize])
	copy(msg.V2[:], v2[:aes.BlockSize])

	return msg
}

func KeySeed2Bytes(msg *KeySeed) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.LittleEndian, msg)
	if err != nil {
		return nil
	}

	return buf.Bytes()
}

func Bytes2KeySeed(b []byte) *KeySeed {
	msg := new(KeySeed)
	buf := bytes.NewReader(b)
	err := binary.Read(buf, binary.LittleEndian, msg)
	if err != nil {
		return nil
	}
	return msg
}

func GenSeedKey(cfg *TunCfg) (*KeySeed, error) {
	seed := new(KeySeed)
	seed.Flag = TUN_FLG
	seed.AesType = uint8(cfg.aesType)
	seed.AesBits = uint8(cfg.aesBits)
	if _, err := io.ReadFull(rand.Reader, seed.R1[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, seed.R2[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, seed.K1[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, seed.V1[:]); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(rand.Reader, seed.K2[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, seed.V2[:]); err != nil {
		return nil, err
	}

	return seed, nil
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

// flag: 1 - enc, 2 - dec
func GenAesStream(k, v []byte, seed *KeySeed, flag int) (cipher.Stream, error) {
	b, err := aes.NewCipher(k[:seed.AesBits])
	if err != nil {
		return nil, err
	}

	var s cipher.Stream
	switch seed.AesType {
	case 1:
		s = cipher.NewCTR(b, v[:])

	case 2:
		if flag == 1 {
			s = cipher.NewCFBEncrypter(b, v[:])
		} else {
			s = cipher.NewCFBDecrypter(b, v[:])
		}

	case 4:
		s = cipher.NewOFB(b, v[:])
	}

	return s, nil
}

func GenAesKey(seedin *KeySeed, cfg *TunCfg) (seed *KeySeed, s1, s2 cipher.Stream, err error) {
	if seedin == nil {
		seed, err = GenSeedKey(cfg)
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		seed = seedin
	}

	msg := KeySeed2KeyMsg(seed)
	var e1, e2 error
	if cfg.tunFlag {
		s1, e1 = GenAesStream(msg.K1[:], msg.V1[:], seed, 2)
		s2, e2 = GenAesStream(msg.K2[:], msg.V2[:], seed, 1)
	} else {
		s1, e1 = GenAesStream(msg.K1[:], msg.V1[:], seed, 1)
		s2, e2 = GenAesStream(msg.K2[:], msg.V2[:], seed, 2)
	}

	if e1 != nil {
		return nil, nil, nil, e1
	}
	if e2 != nil {
		return nil, nil, nil, e2
	}

	return seed, s1, s2, nil
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

		k1, err := AesEncDec(kk, key[:32], ivt[:aes.BlockSize])
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
