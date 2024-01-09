package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
	"sync"
)

func init() {
	Register("tomcat_default_pwd", &tomcat_default_pwd{})
}

type tomcat_default_pwd struct{}

func (p *tomcat_default_pwd) Info() PluginInfo {
	return PluginInfo{
		Name:     "Apahce Tomcat 默认账号",
		VulnInfo: "",
		VulnID:   "",
		Level:    "HIGH",
		URL:      "",
		Version:  "",
		CWE:      "",
	}
}

func (p *tomcat_default_pwd) Check(netloc string) bool {
	base64 := []string{
		"dG9tY2F0OnRvbWNhdA==",
		"YWRtaW46YWRtaW4=",
		"YWRtaW46MTIzNDU2",
	}
	var wg sync.WaitGroup
	resultCh := make(chan bool, len(base64))

	for _, auth := range base64 {
		wg.Add(1)
		go func(auth string) {
			defer wg.Done()

			req, err := http.NewRequest("GET", netloc+"/manager/html", nil)
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Basic "+auth)

			resp, err := utils.RequestDo(req, true, 2)
			if err != nil {
				return
			}

			if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "<title>/manager</title>") {
				resultCh <- true
			}
		}(auth)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for result := range resultCh {
		if result {
			return true
		}
	}

	return false

}
