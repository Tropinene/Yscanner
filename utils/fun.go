package utils

import (
	"math/rand"
	"time"
)

func GenRandom(length int) string {
	rand.NewSource(time.Now().UnixNano())
	var digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" // 所有可能的字符集合
	result := make([]byte, length)                                                // 存放结果的切片

	for i := range result {
		index := rand.Intn(len(digits)) // 从字符集合中随机选取索引位置
		result[i] = digits[index]       // 将对应索引位置上的字符赋值到结果切片中
	}

	return string(result)
}
