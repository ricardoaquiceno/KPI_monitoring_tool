package helpers

import "time"

func IsInInt(s []int, v int) bool {
	for _, i := range s {
		if i == v {
			return true
		}
	}
	return false
}

func MsNearZero(nanosec int) bool {
	milliseconds := nanosec / int(time.Millisecond)
	milliseconds = milliseconds % 1000
	if milliseconds < 50 {
		return true
	} else {
		return false
	}
}
