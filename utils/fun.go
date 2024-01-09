package utils

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// 生成指定位数的随机字符串
func GenRandom(length int) string {
	if length <= 0 {
		return "vivo50"
	}
	rand.NewSource(time.Now().UnixNano())
	var digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" // 所有可能的字符集合
	result := make([]byte, length)                                                // 存放结果的切片

	for i := range result {
		index := rand.Intn(len(digits)) // 从字符集合中随机选取索引位置
		result[i] = digits[index]       // 将对应索引位置上的字符赋值到结果切片中
	}

	return string(result)
}

// 生成指定位数的随机数
func GenRandomInt(length int) int {
	if length <= 0 {
		return 0
	}
	min := int64(1)
	max := int64(1)
	for i := 1; i < length; i++ {
		min *= 10
		max *= 10
	}
	max = max*10 - 1

	return int(min + rand.Int63n(max-min+1))
}

type Bar struct {
	total         int64         // total of task
	current       int64         // current status of task
	filler        string        // filler to progress bar
	filler_size   int           // filler size to progress bar
	filler_length int64         // filler
	interval      time.Duration // interval to print progress
	begin         time.Time     // start of task
}

// New 新建进度条实例
func Newbar(total int64, opts ...func(*Bar)) *Bar {
	bar := &Bar{
		total:         total,
		filler:        "█",
		filler_size:   2,
		filler_length: 26,
		interval:      time.Second,
		begin:         time.Now(),
	}
	for _, opt := range opts {
		opt(bar)
	}

	// 定时打印
	ticker := time.NewTicker(bar.interval)
	go func() {
		for bar.current < bar.total {
			fmt.Print(bar.get_progress_string())
			<-ticker.C
		}
	}()
	return bar
}

// Done 更新完成进度
func (bar *Bar) Done(i int64) {
	bar.current += i
}

// Finish 完成最后进度条
func (bar *Bar) Finish() {
	fmt.Println(bar.get_progress_string())
}

// get_percent 获取进度百分比,区间0-100
func (bar *Bar) get_percent() int64 {
	return bar.current * 100 / bar.total
}

// get_progress_string 获取打印控制台字符串
func (bar *Bar) get_progress_string() string {
	fills := bar.get_percent() * bar.filler_length / 100
	chunks := make([]string, bar.filler_length, bar.filler_length)
	for i := int64(0); i < bar.filler_length; i++ {
		switch {
		case i < fills:
			chunks[i] = bar.filler
		default:
			chunks[i] = " "
		}
	}
	return fmt.Sprintf("\r[%s]%d/%d ", strings.Join(chunks, ""), bar.current, bar.total)
}
