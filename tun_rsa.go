package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func IsDirExist(path string) bool {
	fi, err := os.Stat(path)

	if err != nil {
		return os.IsExist(err)
	}

	return fi.IsDir()
}

func IsFileExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

// Read RSA key file
func RsaReadKey(keyName string) []byte {
	key, err := ioutil.ReadFile(keyName)
	if err != nil {
		return nil
	}

	return key
}

// Gen RSA key pair
func RsaGenKey(filePath string, bits int) error {

	if !IsDirExist(filePath) {
		os.Mkdir(filePath, 0700)
	}

	privPath := filepath.Join(filePath, "private.pem")
	pubfPath := filepath.Join(filePath, "public.pem")
	if IsFileExist(privPath) || IsFileExist(pubfPath) {
		log.Println("Error: files already exist at:", filePath)
		return errors.New("RSA key files already exist")
	}

	// Gen private key
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	file, err := os.Create(privPath)
	if err != nil {
		log.Println("Error: create ", privPath, " failed")
		return err
	}
	defer file.Close()

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	file.Chmod(0400)

	// Gen public key
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	file, err = os.Create(pubfPath)
	if err != nil {
		log.Println("Error: create ", pubfPath, " failed")
		return err
	}
	defer file.Close()

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	file.Chmod(0400)
	return nil
}

// RSA encrypt
func RsaEncrypt(publicKey []byte, origData []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub := pubInterface.(*rsa.PublicKey)
	k := (pub.N.BitLen() + 7) / 8 // RSA Len / 8
	if len(origData) > k-11 {
		o1, e1 := rsa.EncryptPKCS1v15(rand.Reader, pub, origData[:k-19])
		o2, e2 := rsa.EncryptPKCS1v15(rand.Reader, pub, origData[k-19:])
		if e1 != nil || e2 != nil {
			return nil, errors.New("RSA encrypt error")
		}
		return append(o1, o2...), nil
	} else {
		return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
	}
}

// RSA decrypt
func RsaDecrypt(privateKey []byte, ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	k := (priv.N.BitLen() + 7) / 8 // RSA Len / 8
	if len(ciphertext) > k {
		o1, e1 := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext[:k])
		o2, e2 := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext[k:])
		if e1 != nil || e2 != nil {
			return nil, errors.New("RSA decrypt error")
		}
		return append(o1, o2...), nil
	} else {
		return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	}
}

// RSA public key size
func RsaPublicSize(fileName string) (int, error) {
	publicKey := RsaReadKey(fileName)
	if publicKey == nil {
		return 0, errors.New("RsaReadKey failed")
	}

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return 0, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return 0, err
	}

	pub := pubInterface.(*rsa.PublicKey)
	k := (pub.N.BitLen() + 7) / 8 // RSA Len / 8
	return k, nil
}

// RSA private key size
func RsaPrivateSize(fileName string) (int, error) {
	privateKey := RsaReadKey(fileName)
	if privateKey == nil {
		return 0, errors.New("RsaReadKey failed")
	}

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return 0, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return 0, err
	}

	k := (priv.N.BitLen() + 7) / 8 // RSA Len / 8
	return k, nil
}
