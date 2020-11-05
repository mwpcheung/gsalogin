package main

import (
	"log"

	"howett.net/plist"
)

type GSARequestCPD struct {
	CID          string `plist:"AppleIDClientIdentifier"`
	ClientTime   string `plist:"X-Apple-I-Client-Time"` //rfc3330
	IMD          string `plist:"X-Apple-I-MD"`
	IMDM         string `plist:"X-Apple-I-MD-M"`
	RInfo        int    `plist:"X-Apple-I-MD-RINFO"`
	SerialNumber string `plist:"X-Apple-I-SRL-NO,omitempty"`
	UDID         string `plist:"X-Mme-Device-Id"`
	BootStrap    bool   `plist:"bootstrap"`
	CApp         string `plist:"capp,omitempty"`
	CKGen        bool   `plist:"ckgen,omitempty"`
	DC           string `plist:"dc,omitempty"`
	DEC          string `plist:"dec,omitempty"`
	Loc          string `plist:"loc,omitempty"`
	PApp         string `plist:"papp,omitempty"`
	PBE          bool   `plist:"pbe,omitempty"`
	PRKGEN       bool   `plist:"prkgen,omitempty"`
	PRTN         string `plist:"prtn,omitempty"`
	SVCT         string `plist:"svct,omitempty"`
}
type GSAStep1Request struct {
	A2K        []byte         `plist:"A2k"`
	Operation  string         `plist:"o"`
	ProtoStyle []string       `plist:"ps"`
	UserName   string         `plist:"u"`
	CPD        *GSARequestCPD `plist:"cpd"`
}

//GSAStep1Response step1 resp
type GSAStep1Response struct {
	Status         GSAStatus `plist:"Status"`
	IterationCount int       `plist:"i"`
	Salt           []byte    `plist:"s"`
	SeverProto     string    `plist:"sp"`
	Complete       string    `plist:"c"`
	SRPB           []byte    `plist:"B"`
}

//GSAStatus status
type GSAStatus struct {
	StatusCode      int    `plist:"hsc"`
	ErrorDescrption string `plist:"ed"`
	ErrorCode       int    `plist:"ec"`
	ErrorMessage    string `plist:"em"`
}
type GSAStep2Request struct {
	M1        []byte        `plist:"M1"`
	Complete  string        `plist:"c"`
	Operation string        `plist:"o"`
	UserName  string        `plist:"u"`
	CPD       GSARequestCPD `plist:"cpd"`
}

type GSAStep2Response struct {
	Status GSAStatus `plist:"Status"`
	SPD    []byte    `plist:"spd"`
	M2     []byte    `plist:"M2"`
	NP     []byte    `plist:"np"`
}
type ReqVersion struct {
	Version string `plist:"Version"`
}

func PostLoginStep1Request(req *GSAStep1Request) *GSAStep1Response {
	if req == nil {
		return nil
	}
	type Request struct {
		Header  ReqVersion       `plist:"Header"`
		Request *GSAStep1Request `plist:"Request"`
	}
	var request Request
	request.Header.Version = "1.0.1"
	request.Request = req
	body, err := plist.MarshalIndent(&request, plist.XMLFormat, "\t")
	if err != nil {
		log.Printf("format plist failed %v", err)
		return nil
	}
	uri := "https://gsa.apple.com/grandslam/GsService2"
	h := NewHeader()
	h.Header["User-Agent"] = []string{"akd/1.0 CFNetwork/808.2.16 Darwin/16.3.0"}
	h.Header["X-MMe-Client-Info"] = []string{"<iPhone7,2> <iPhone OS;10.2;14C92> <com.apple.akd/1.0 (com.apple.akd/1.0)>"}
	h.Header["Accept-Language"] = []string{"zh-cn"}
	h.Header["Content-Type"] = []string{"text/x-xml-plist"}
	proxy := Proxy{Type: HTTP, Address: "http://localhost:8888"}
	_, respBody, err := WebRequestMethod(uri, "POST", &proxy, &h.Header, nil, body)
	if err != nil {
		log.Printf("返回错误 %v", err)
		return nil
	}
	type Response struct {
		Response *GSAStep1Response `plist:"Response"`
	}
	var respone Response
	plist.Unmarshal(respBody, &respone)
	return respone.Response
}
func PostLoginStep2Request(req *GSAStep2Request) *GSAStep2Response {
	if req == nil {
		return nil
	}
	type Request struct {
		Header  ReqVersion       `plist:"Header"`
		Request *GSAStep2Request `plist:"Request"`
	}
	var request Request
	request.Header.Version = "1.0.1"
	request.Request = req
	body, _ := plist.MarshalIndent(&request, plist.XMLFormat, "\t")
	uri := "https://gsa.apple.com/grandslam/GsService2"
	h := NewHeader()
	h.Header["User-Agent"] = []string{"akd/1.0 CFNetwork/808.2.16 Darwin/16.3.0"}
	h.Header["X-MMe-Client-Info"] = []string{"<iPhone7,2> <iPhone OS;10.2;14C92> <com.apple.akd/1.0 (com.apple.akd/1.0)>"}
	h.Header["Accept-Language"] = []string{"zh-cn"}
	h.Header["Content-Type"] = []string{"text/x-xml-plist"}
	proxy := Proxy{Type: HTTP, Address: "http://localhost:8888"}
	_, respBody, err := WebRequestMethod(uri, "POST", &proxy, &h.Header, nil, body)
	if err != nil {
		log.Printf("返回错误 %v", err)
		return nil
	}
	type Response struct {
		Response *GSAStep2Response `plist:"Response"`
	}
	var respone Response
	plist.Unmarshal(respBody, &respone)
	return respone.Response
}
