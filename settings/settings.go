package settings

type Socks5ClientSetting struct {
	Server     string `json:"server"`
	ServerPort int    `json:"serverport"`
	Local      string `json:"local"`
	LocalPort  int    `json:"localport"`
	User       string `json:"user"`
	PassWord   string `json:"password"`
}

type Socks5ServerSettings struct {
	Server     string `json:"server"`
	ServerPort int    `json:"serverport"`
	PassWord   string `json:"password"`
}
