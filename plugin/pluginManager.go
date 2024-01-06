// goplugin/pluginregistry.go
package goplugin

import (
	"fmt"
	"sync"
)

// 插件接口
type Plugin interface {
	Info() PluginInfo
	Check(netloc string) bool
}

// 插件管理器
type PluginManager struct {
	plugins map[string]Plugin
	mu      sync.Mutex
}

// 插件信息结构体
type PluginInfo struct {
	Name     string
	VulnInfo string
	VulnID   string
	Level    string
	URL      string
	Version  string
	CWE      string
}

var (
	registry     = make(map[string]Plugin)
	registryLock sync.Mutex
)

// Register 将插件注册到插件管理器
func Register(name string, plugin Plugin) {
	registryLock.Lock()
	defer registryLock.Unlock()
	registry[name] = plugin
}

// GetPlugins 获取所有已注册的插件
func GetAllPlugins() []Plugin {
	registryLock.Lock()
	defer registryLock.Unlock()

	var plugins []Plugin
	for _, plugin := range registry {
		plugins = append(plugins, plugin)
	}

	return plugins
}

// 函数用于根据 VulnID 返回对应的插件
func GetPluginByVulnID(vulnID string) Plugin {
	plugins := GetAllPlugins()
	for _, plugin := range plugins {
		if plugin.Info().VulnID == vulnID {
			return plugin
		}
	}
	return nil
}

// NewPluginManager 创建一个插件管理器
func NewPluginManager() *PluginManager {
	return &PluginManager{
		plugins: make(map[string]Plugin),
	}
}

// Register 将插件注册到插件管理器
func (pm *PluginManager) Register(plugin Plugin) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	info := plugin.Info()
	pm.plugins[info.Name] = plugin
}

// ExecuteAll 执行所有插件
func (pm *PluginManager) ExecuteAll(netloc string, is_file bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, plugin := range pm.plugins {
		res := plugin.Info()
		if !is_file {
			fmt.Printf("[*] 检查 %s\n", res.Name)
		}
		// 执行插件
		if plugin.Check(netloc) {
			fmt.Printf("\033[1;31m[+] %s 存在 %s \033[35m%s\033[33m\n", netloc, res.Name, res.Level)
		} else {
			if !is_file {
				fmt.Printf("\033[1;36m[-] %s 不存在 %s\033[0m\n", netloc, res.Name)
			}
		}
	}
}
