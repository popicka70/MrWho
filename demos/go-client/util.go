package main

import (
	"encoding/json"
	"fmt"
)

func prettyJSON(v any) string {
	if v == nil {
		return ""
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("<error: %v>", err)
	}
	return string(data)
}
