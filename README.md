# Yscanner
一个基于go的简易漏洞检测器。

个人平时就有写PoC的需求，手里捏的PoC多了以后就想把他们整合起来。github上有不少极其优秀的基于golang的PoC检测框架如Kunpeng、Roby等。但是这些框架对于我个人而言有些过于复杂了，于是写了这个简易框架。
## 使用
运行全部插件
```bash
go run main.go -t http://127.0.0.1
```
运行指定漏洞检测插件
```bash
go run main.go -t http://127.0.0.1 -v CVE-2023-35843
```
从文件中读入大量url检测
```bash
go run main.go -f urls.txt
```
展示支持的检测插件
```bash
go run main.go -s
```
## 支持漏洞列表
1