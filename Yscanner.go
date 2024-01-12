// main.go
package main

import (
	goplugin "Yscanner/plugin"
	"Yscanner/utils"
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	welcome()

	tFlag := flag.String("t", "", "待检测url, 例如http://127.0.0.1")
	vFlag := flag.String("v", "", "载入指定漏洞编号的插件，不指定默认全部检测")
	pFlag := flag.String("p", "", "按指纹载入插件")
	fFlag := flag.String("f", "", "存储检测url的文件")
	showFlag := flag.Bool("s", false, "展示所有检测插件")

	// 解析命令行参数
	flag.Parse()

	if *showFlag {
		showPlugins()
		return
	}

	// 检查是否提供了必须的参数 -t
	if *tFlag == "" && *fFlag == "" {
		fmt.Println("\033[1;35m[ERROR] 缺少检测目标\033[0m")
		return
	}
	if *tFlag != "" && *fFlag != "" {
		fmt.Println("\033[1;35m[ERROR] 检测目标重复\033[0m")
		return
	}

	var plugins []goplugin.Plugin

	// 如果提供了 -v 参数，只获取对应的插件
	if *vFlag != "" {
		// 获取对应的插件
		targetPlugin := goplugin.GetPluginByVulnID(*vFlag)
		if targetPlugin == nil {
			fmt.Printf("\033[1;35m[ERROR] 未找到对应VulnID的插件: %s\033[0m\n", *vFlag)
			return
		}
		plugins = append(plugins, targetPlugin)
	} else if *pFlag != "" {
		targetPlugin := goplugin.GetPluginByFingerprint(*pFlag)
		if targetPlugin == nil {
			fmt.Printf("\033[1;35m[ERROR] 未找到对应指纹的插件: %s\033[0m\n", *pFlag)
			return
		}
		plugins = targetPlugin
	} else {
		// 如果没有提供 -v 参数，获取所有插件
		plugins = goplugin.GetAllPlugins()
	}

	// 创建插件管理器
	pm := goplugin.NewPluginManager()

	// 注册插件
	for _, plugin := range plugins {
		// fmt.Printf("[+] Registering plugin: %s\n", plugin.Info().Name)
		pm.Register(plugin)
	}

	// 执行所有插件
	if *tFlag != "" {
		// todo 这里只有检测结束了才回输出结果，等待过程有点无聊
		start := time.Now()
		res := pm.ExecuteAll(*tFlag, false)
		for _, info := range res {
			fmt.Println(info)
		}
		elapsed := time.Since(start).Seconds()
		fmt.Printf("检测所用时间: %fs\n", elapsed)
	}
	if *fFlag != "" {
		urls, err := readLinesWithoutNewline(*fFlag)
		if err != nil {
			fmt.Printf("\033[1;35m[Error] %v\033[0m\n", err)
			return
		}
		fmt.Printf("[*] Check %d urls...\n", len(urls))
		start := time.Now()

		// 增加了一个进度条，但是好像不是很顺滑
		bar := utils.Newbar(int64(len(urls)))
		var wg sync.WaitGroup
		for _, url := range urls {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				res := pm.ExecuteAll(u, true)
				for _, info := range res {
					fmt.Println(info)
				}

				bar.Done(1)
			}(url)
		}
		wg.Wait()
		bar.Finish()

		elapsed := time.Since(start).Seconds()
		fmt.Printf("检测所用时间: %.1fs\n", elapsed)
	}
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

// func removeNewline(input string) string {
// 	return strings.TrimRight(input, "\n")
// }

func readLinesWithoutNewline(filePath string) ([]string, error) {
	var lines []string

	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("\033[1;35m[ERROR] 无法打开文件: %v\033[0m", err)
	}
	defer file.Close()

	// 创建一个带缓冲的读取器
	scanner := bufio.NewScanner(file)

	// 逐行读取文件内容
	for scanner.Scan() {
		line := scanner.Text()
		// 调用函数删除末尾的换行符
		line = strings.TrimRight(line, "\n")
		line = strings.TrimRight(line, "\\")
		lines = append(lines, line)
	}

	// 检查是否有读取错误
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("\033[1;35m[ERROR] 读取文件时发生错误: %v\033[0m", err)
	}

	return lines, nil
}

func showPlugins() {
	plugins := goplugin.GetAllPlugins()

	// 打印每个插件的信息
	for idx, plugin := range plugins {
		info := plugin.Info()
		fmt.Printf("[%d] %s\n", idx+1, info.Name)
	}
}
