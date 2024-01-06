// main.go
package main

import (
	goplugin "Yscanner/plugin"
	"flag"
	"fmt"
)

func main() {
	welcome()

	tFlag := flag.String("t", "", "待检测url, 例如http://127.0.0.1")
	vFlag := flag.String("v", "", "检测的漏洞，不指定默认全部检测")

	// 解析命令行参数
	flag.Parse()

	// 检查是否提供了必须的参数 -t
	if *tFlag == "" {
		fmt.Println("错误：缺少必须的参数 -t")
		return
	}

	var plugins []goplugin.Plugin

	// 如果提供了 -v 参数，只获取对应的插件
	if *vFlag != "" {
		// 获取对应的插件
		targetPlugin := goplugin.GetPluginByVulnID(*vFlag)
		if targetPlugin == nil {
			fmt.Println("[-] 未找到对应VulnID的插件")
			return
		}
		plugins = append(plugins, targetPlugin)
	} else {
		// 如果没有提供 -v 参数，获取所有插件
		plugins = goplugin.GetAllPlugins()
	}

	// 创建插件管理器
	pm := goplugin.NewPluginManager()

	// 注册插件
	for _, plugin := range plugins {
		// fmt.Printf("[+] Registering plugin: %s\n", name)
		pm.Register(plugin)
	}

	// 执行所有插件
	pm.ExecuteAll(*tFlag)
}

func welcome() {
	banner := `
	▓██   ██▓  ██████  ▄████▄   ▄▄▄       ███▄    █  ███▄    █ ▓█████  ██▀███  
	 ▒██  ██▒▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █  ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
	  ▒██ ██░░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
	  ░ ▐██▓░  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄  
	  ░ ██▒▓░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░▒██░   ▓██░░▒████▒░██▓ ▒██▒
	   ██▒▒▒ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
	 ▓██ ░▒░ ░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
	 ▒ ▒ ░░  ░  ░  ░  ░          ░   ▒      ░   ░ ░    ░   ░ ░    ░     ░░   ░ 
	 ░ ░           ░  ░          ░   ░          ░          ░      ░     ░    ░     
	 ░ ░              ░              ░                                              
	`
	fmt.Println(banner)
}
