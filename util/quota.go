package util

import (
	"strconv"
	"strings"
)

func ParseQuotaToMB(quotaStr string) float64 {
	quotaStr = strings.TrimSpace(quotaStr)
	if quotaStr == "" || quotaStr == "0" {
		return 0
	}

	parts := strings.SplitN(quotaStr, " ", 2)
	if len(parts) != 2 {
		val, err := strconv.ParseFloat(quotaStr, 64)
		if err == nil {
			return val
		}
		return 0
	}

	valStr := strings.ReplaceAll(parts[0], ",", "")
	val, err := strconv.ParseFloat(valStr, 64)
	if err != nil {
		return 0
	}

	unit := strings.ToUpper(strings.TrimSpace(parts[1]))
	switch unit {
	case "GB":
		return val * 1024
	case "MB":
		return val
	case "KB":
		return val / 1024
	case "TB":
		return val * 1024 * 1024
	default:
		return val
	}
}
