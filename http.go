package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	goproxy "golang.org/x/net/proxy"
)

type ProxyType int

const (
	HTTP   ProxyType = 0
	SOCKS5 ProxyType = 1
)

type Proxy struct {
	Type    ProxyType
	Address string
}

//HTTPHeader reclass header
type HTTPHeader struct {
	http.Header
	MDM, MD   []byte
	IMDM, IMD []byte
	AMDM, AMD []byte
	UDID      string
}

func header() *http.Header {
	header := &http.Header{}

	return header
}

//NewHeader 新分配一个header
func NewHeader() *HTTPHeader {
	h := HTTPHeader{Header: *header(), MDM: nil, MD: nil, IMDM: nil, IMD: nil, AMDM: nil, AMD: nil, UDID: ""}
	h.AddDefault()
	return &h
}

//AddDefault 增加默认头
func (h *HTTPHeader) AddDefault() {
	h.Header["Accept-Encoding"] = []string{"gzip, deflate"}
	h.Header["Accept-Language"] = []string{"en-us"}
	h.Header["Accept"] = []string{"*/*"}
	h.Header["Connection"] = []string{"keep-alive"}
}

//WebRequestMethod Http
func WebRequestMethod(uri string, method string, proxy *Proxy, headers *http.Header, cookieJar http.CookieJar, body []byte) (*http.Header, []byte, error) {
	var lastError error
	var bodyBytes []byte
	lastError = nil
	var h http.Header
	dialer := net.Dialer{Timeout: time.Duration(time.Second * 20), KeepAlive: 0}
	for i := 0; i < 3; i++ {

		request, err := http.NewRequest(method, uri, bytes.NewBuffer(body))
		if err != nil {
			lastError = err
			continue
		}
		request.Close = true
		if headers != nil {
			request.Header = *headers
		}

		transport := &http.Transport{
			Dial:                  dialer.Dial,
			TLSHandshakeTimeout:   time.Duration(time.Second * 30),
			ResponseHeaderTimeout: time.Duration(20 * time.Second),
			ExpectContinueTimeout: time.Duration(5 * time.Second),
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:     true,
		}
		if proxy != nil {

			if proxy.Type == HTTP {
				proxyURL, err := url.Parse(proxy.Address)
				if err != nil {
					lastError = err
					continue
				}
				transport.Proxy = http.ProxyURL(proxyURL)

			} else {
				dialer, _ := goproxy.SOCKS5("tcp", proxy.Address, nil, goproxy.Direct)
				transport.Dial = dialer.Dial
			}
		}
		client := &http.Client{
			Transport: transport,
			Timeout:   time.Duration(time.Second * 60),
			Jar:       cookieJar,
		}
		response, err := client.Do(request)

		if err != nil {
			lastError = err
			continue
		}
		if headers != nil {
			// *headers = response.Header
		}
		defer response.Body.Close()
		h = response.Header
		// if response.StatusCode != 200 {

		// 	return nil, fmt.Errorf("response status code: %d", response.StatusCode), &h
		// }
		switch response.Header.Get("Content-Encoding") {
		case "gzip":
			reader, err := gzip.NewReader(response.Body)
			if err != nil {
				lastError = err
				continue
			}
			body, err := ioutil.ReadAll(reader)
			if err != nil {
				lastError = err
				continue
			}
			bodyBytes = body
		default:
			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				lastError = err
				continue
			}
			bodyBytes = body
		}
		if response.StatusCode != 200 {

			err = fmt.Errorf("response status code: %d", response.StatusCode)
		}
		return &h, bodyBytes, err
	}
	if lastError != nil {
		body = nil
	}
	return &h, body, lastError
}
