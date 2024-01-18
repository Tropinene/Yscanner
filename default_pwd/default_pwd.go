package default_pwd

import (
	"Yscanner/utils"
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

type JSONData struct {
	Name   string   `json:"name"`
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Body   string   `json:"body"`
	Check  []string `json:"check"`
}

func Default_login(netloc, finger_print string) (string, bool) {
	dict, err := findMatchingData(finger_print)
	if err != nil {
		// fmt.Printf("\033[1;35m[ERROR] %v\033[0m\n", err)
		return "", false
	}
	req, err := http.NewRequest(dict.Method, netloc+dict.Path, bytes.NewBufferString(dict.Body))
	if err != nil {
		return dict.Name, false
	}
	resp, err := utils.RequestDo(req, true, 3)
	if err != nil {
		return dict.Name, false
	}
	if resp.Other.StatusCode == 200 {
		for _, check_str := range dict.Check {
			if !strings.Contains(resp.ResponseRaw, check_str) {
				return dict.Name, false
			}
		}
		return dict.Name, true
	}
	return dict.Name, false
}

func findMatchingData(finger_print string) (*JSONData, error) {
	// Read JSON data from default_pwd.json
	fileContent, err := os.ReadFile("./default_pwd/default_pwd.json")
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON data into a slice of JSONData structs
	var jsonDataList []JSONData
	err = json.Unmarshal(fileContent, &jsonDataList)
	if err != nil {
		return nil, err
	}

	// Find matching data based on the target
	for _, data := range jsonDataList {
		name := strings.ToLower(data.Name)
		finger_print = strings.ToLower(finger_print)
		if strings.Contains(name, finger_print) {
			if err != nil {
				return nil, err
			}
			return &data, nil
		}
	}

	return nil, nil
}
