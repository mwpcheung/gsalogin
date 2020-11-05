package main

import "testing"

func TestHttpGet(t *testing.T) {
	uri := "https://google.com"
	_, respBody, err := WebRequestMethod(uri, "GET", nil, nil, nil, nil)
	if err != nil {
		t.Errorf("get response failed %+v", err)
	} else {
		t.Logf("download %d bytes from google.com", len(respBody))
	}
}

func TestHttpPostWithProxy(t *testing.T) {
	uri := "https://google.com"
	proxy := &Proxy{Type: HTTP, Address: "http://localhost:8888"}
	_, respBody, err := WebRequestMethod(uri, "GET", proxy, nil, nil, nil)
	if err != nil {
		t.Errorf("get response failed %+v", err)
	} else {
		t.Logf("download %d bytes from google.com", len(respBody))
	}
}
