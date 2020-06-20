package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
)

type SRPClient struct {
	Params     *SRPParams
	Secret1    *big.Int
	Multiplier *big.Int
	A          *big.Int
	X          *big.Int
	M1         []byte
	M2         []byte
	K          []byte
	u          *big.Int
	s          *big.Int
}

func NewSRPClient(param *SRPParams, a []byte) *SRPClient {
	if len(a) == 0 {
		a = make([]byte, 32)
		rand.Read(a)
	}
	sec := a
	multiplier := param.getMultiplier()
	secret1Int := intFromBytes(sec)
	Ab := param.calculateA(secret1Int)
	A := intFromBytes(Ab)
	return &SRPClient{
		Params:     param,
		Multiplier: multiplier,
		Secret1:    secret1Int,
		A:          A,
	}
}

//ProcessClientChanllenge username,password,salt,B  计算K 和M1
func (kls *SRPClient) ProcessClientChanllenge(username, password, salt, B []byte) {
	c := kls
	c.X = c.Params.calculateX(salt, username, password)
	bigB := intFromBytes(B)
	u := c.Params.calculateU(c.A, bigB)
	k := c.Multiplier
	S := c.Params.calculateS(k, c.X, c.Secret1, bigB, u)
	c.K = c.Params.calculateK(S)
	c.u = u               // Only for tests
	c.s = intFromBytes(S) // Only for tests
	A := padToN(c.A, c.Params)
	c.M1 = c.Params.calculateM1(username, salt, A, B, c.K)
	c.M2 = c.Params.calculateM2(A, c.M1, c.K)
}

func (c *SRPClient) GetABytes() []byte {
	return padToN(c.A, c.Params)
}

func (c *SRPClient) GetM1Bytes() []byte {
	return c.M1
}

func (c *SRPClient) GetSessionKey() []byte {
	return c.K
}

func (c *SRPClient) CheckM2(M2 []byte) error {
	if !bytes.Equal(c.M2, M2) {
		return errors.New("M2 didn't check")
	} else {
		return nil
	}
}
