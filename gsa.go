package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"time"

	"github.com/mwpcheung/dict"

	"golang.org/x/crypto/pbkdf2"
)

//AppleLoginContext apple gsa login
type AppleLoginContext struct {
	Exchange hash.Hash
	Proto    []string
	srp      *SRPClient
	UserName []byte
	Password []byte
	CPD      *GSARequestCPD
	DCH      bool
	SC       []byte
}

func NewLoginSession(username, password string) *AppleLoginContext {
	context := new(AppleLoginContext)
	param := GetParams(2048)
	param.NoUserNameInX = true
	context.srp = NewSRPClient(param, nil)
	context.UserName = []byte(username)
	context.Password = []byte(password)
	context.Exchange = sha256.New()
	return context
}
func (kls *AppleLoginContext) UpdateNegData(data []byte) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(len(data)))
	kls.Exchange.Write(buf.Bytes())
	kls.Exchange.Write(data)
}
func (kls *AppleLoginContext) UpdateNegString(s string) {
	kls.Exchange.Write([]byte(s))
}

func (kls *AppleLoginContext) ClientStep1() dict.Dict {
	for i, proto := range kls.Proto {
		kls.UpdateNegString(proto)
		if i != len(kls.Proto)-1 {
			kls.UpdateNegString(",")
		}
	}
	return nil

}
func (kls *AppleLoginContext) createSessionKey(keyname string) []byte {
	skey := kls.srp.GetSessionKey()
	mac := hmac.New(sha256.New, skey)
	mac.Write([]byte(keyname))
	expectedMAC := mac.Sum(nil)
	return expectedMAC
}

//Decrypt 解密srp 传输的数据
func (kls *AppleLoginContext) Decrypt(spd []byte) []byte {
	key := kls.createSessionKey("extra data key:")
	iv := kls.createSessionKey("extra data iv:")
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(iv) >= block.BlockSize() {

		iv = iv[:block.BlockSize()]
	} else {
		iv = make([]byte, block.BlockSize())
	}
	ciphertext := spd
	plaintext := make([]byte, len(ciphertext))
	bm := cipher.NewCBCDecrypter(block, iv)
	bm.CryptBlocks(plaintext, ciphertext)
	plaintext, _ = pkcs7Unpad(plaintext, block.BlockSize())
	return plaintext
}

func (kls *AppleLoginContext) LoginStep1(udid, imd, imdm string) *GSAStep1Response {
	var req GSAStep1Request
	var cpd GSARequestCPD
	{
		req.A2K = kls.srp.A.Bytes()
		cpd.CID = "649B8728-B398-4A6A-835A-5517488C3F9A"
		cpd.ClientTime = time.Now().UTC().Format("2006-01-02T15:04:05Z")
		cpd.IMD = imd
		cpd.IMDM = imdm
		cpd.RInfo = 17106176
		cpd.BootStrap = true
		cpd.CKGen = true
		cpd.UDID = udid
		kls.CPD = &cpd
	}
	req.CPD = &cpd
	req.ProtoStyle = []string{"s2k", "s2k_fo"}
	req.UserName = string(kls.UserName)
	req.Operation = "init"

	for i, name := range req.ProtoStyle {
		kls.UpdateNegString(name)
		if i != len(req.ProtoStyle)-1 {
			kls.UpdateNegString(",")
		}
	}
	kls.UpdateNegString("|")
	if kls.DCH {
		kls.UpdateNegString("DisregardChannelBindings")
	}
	resp := PostLoginStep1Request(&req)
	return resp
}

func (kls *AppleLoginContext) LoginStep2(m1 []byte, c string, sp string) *GSAStep2Response {
	var req GSAStep2Request
	req.CPD = *kls.CPD
	req.M1 = m1
	req.Operation = "complete"
	req.Complete = c
	req.UserName = string(kls.UserName)
	kls.UpdateNegString("|")
	kls.UpdateNegString(sp)
	resp := PostLoginStep2Request(&req)
	return resp
}

//HandleStep1 处理登陆第一步,返回M1
func (kls *AppleLoginContext) HandleStep1(resp *GSAStep1Response) []byte {
	if resp != nil {
		salt := resp.Salt
		// c := resp.Complete
		iter := resp.IterationCount
		nots2k := true
		if resp.SeverProto == "s2k" {
			nots2k = false
		}
		key := SRPPassword(sha256.New, nots2k, string(kls.Password), salt, iter)
		kls.srp.ProcessClientChanllenge(kls.UserName, key, salt, resp.SRPB)
		return kls.srp.GetM1Bytes()
	}
	return nil
}
func (kls *AppleLoginContext) HandleStep2(resp *GSAStep2Response) []byte {
	kls.UpdateNegString("|")
	kls.UpdateNegData(resp.SPD)
	kls.UpdateNegString("|")
	if len(kls.SC) > 0 {
		kls.UpdateNegData(kls.SC)
	}
	kls.UpdateNegString("|")
	if len(resp.SPD) > 0 {
		return kls.Decrypt(resp.SPD)
	}
	return nil
}

//SRPPassword 计算srp P 字段， 密码用明文经多次sha256 迭代所得  s2kfo sp field not equal to s2k set true
func SRPPassword(h func() hash.Hash, s2kfo bool, password string, salt []byte, iterationcount int) []byte {
	hashPass := sha256.New()
	hashPass.Write([]byte(password))
	var digest []byte
	if s2kfo {
		digest = []byte(hex.EncodeToString(hashPass.Sum(nil)))
	} else {
		digest = hashPass.Sum(nil)
	}
	return pbkdf2.Key(digest, salt, iterationcount, h().Size(), h)
}
