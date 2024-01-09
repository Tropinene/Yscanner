package utils

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httputil"
	"time"
)

// Resp 封装的http返回包
type Resp struct {
	Body        []byte
	Other       *http.Response
	RequestRaw  string
	ResponseRaw string
}

func RequestDo(request *http.Request, hasRaw bool, timeout time.Duration) (Resp, error) {
	var result Resp
	var err error
	// request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36")
	if hasRaw {
		requestOut, err := httputil.DumpRequestOut(request, true)
		if err == nil {
			result.RequestRaw = string(requestOut)
		}
	}
	transport := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	var client = &http.Client{
		Timeout:   time.Second * timeout,
		Transport: transport,
	}
	result.Other, err = client.Do(request)
	if err != nil {
		return result, err
	}

	result.Body, _ = io.ReadAll(result.Other.Body)
	result.Other.Body.Close()
	if hasRaw {
		result.ResponseRaw = string(result.Body)
	}
	return result, err
}
