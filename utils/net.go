package utils

import (
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
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36")
	if hasRaw {
		requestOut, err := httputil.DumpRequestOut(request, true)
		if err == nil {
			result.RequestRaw = string(requestOut)
		}
	}
	var client = &http.Client{Timeout: time.Second * timeout}
	result.Other, err = client.Do(request)
	if err != nil {
		return result, err
	}
	defer result.Other.Body.Close()

	if hasRaw {
		ResponseOut, err := httputil.DumpResponse(result.Other, true)
		if err == nil {
			result.ResponseRaw = string(ResponseOut)
		}
	}
	result.Body, _ = io.ReadAll(result.Other.Body)
	return result, err
}