package settings

import (
	"encoding/json"
	"io"
	"os"
)

type Settings struct {
	Server struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		Method   string `json:"method"`
		Udpport  int    `json:"udpport"`
	} `json:"server"`
	Client struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		Udpport  int    `json:"udpport"`
	} `json:"client"`
}

func Parse(path string) (config *Settings, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	config = &Settings{}
	if err = json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}
