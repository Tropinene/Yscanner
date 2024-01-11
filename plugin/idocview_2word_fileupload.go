package goplugin

import (
	"Yscanner/utils"
	"crypto/md5"
	"fmt"
	"net/http"
	"strings"
)

func init() {
	Register("idocview_2word_fileupload", &idocview_2word_fileupload{})
}

type idocview_2word_fileupload struct{}

func (p *idocview_2word_fileupload) Info() PluginInfo {
	return PluginInfo{
		Name:     "I Doc View 任意文件上传漏洞",
		VulnInfo: "I Doc View在线文档预览系统是一套用于在Web环境中展示和预览各种文档类型的系统，如文本文档、电子表格、演示文稿、PDF文件等。攻击者可利用该漏洞使服务器下载恶意文件，执行任意代码。",
		VulnID:   "",
		Level:    "HIGH",
		URL:      "https://mp.weixin.qq.com/s/i7IHgq4fn795NghY-aYg5A",
		Version:  "iDocView < 13.10.1_20231115",
		CWE:      "CWE-434	危险类型文件的不加限制上传",
	}
}

func (p *idocview_2word_fileupload) Check(netloc string) bool {
	randName := utils.GenRandom(10)
	req, err := http.NewRequest("GET", netloc+"/html/2word?url="+randName, nil)
	if err != nil {
		return false
	}
	resp, err := utils.RequestDo(req, true, 5) // 这个检测需要将近5s
	if err != nil {
		return false
	}

	md5 := md5.Sum([]byte(randName))
	md5str := fmt.Sprintf("%x", md5)
	if resp.Other.StatusCode == 200 && strings.Contains(resp.Other.Header["Content-Disposition"][0], md5str) {
		return true
	}
	return false
}
