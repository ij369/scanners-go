package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/getlantern/systray"
	"github.com/gorilla/websocket"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/sys/windows/registry"
)

//go:embed static
var staticFiles embed.FS

//go:embed icon.ico
var iconBytes []byte

var (
	user32                  = syscall.NewLazyDLL("user32.dll")
	procSetWindowsHookEx    = user32.NewProc("SetWindowsHookExW")
	procCallNextHookEx      = user32.NewProc("CallNextHookEx")
	procUnhookWindowsHookEx = user32.NewProc("UnhookWindowsHookEx")
	procGetMessage          = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessage     = user32.NewProc("DispatchMessageW")
	keyboardHook            uintptr
	input                   strings.Builder
	lastKeyTime             time.Time
)

const (
	WH_KEYBOARD_LL = 13
	WM_KEYDOWN     = 256
	WM_KEYUP       = 257
	WM_SYSKEYDOWN  = 260
	WM_SYSKEYUP    = 261
	VK_RETURN      = 0x0D
	VK_TAB         = 0x09
	VK_CAPITAL     = 0x14
	VK_SHIFT       = 0x10
	VK_LSHIFT      = 0xA0
	VK_RSHIFT      = 0xA1
)

var (
	leftShiftPressed  bool
	rightShiftPressed bool
	capsLockOn        bool
)

type KBDLLHOOKSTRUCT struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

type MSG struct {
	Hwnd    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
}

type Config struct {
	ForwardURL       string `json:"forwardURL"`
	ResetInterval    int    `json:"resetInterval"`
	Port             int    `json:"port"`
	AutoOpenPage     bool   `json:"autoOpenPage"`
	ShowSpecialChars bool   `json:"showSpecialChars"`
	ShowConsole      bool   `json:"showConsole"`
	StartOnBoot      bool   `json:"startOnBoot"`
	mu               sync.RWMutex
}

var (
	config = Config{
		ForwardURL:       "http://localhost:5000/scanner/endpoint",
		ResetInterval:    500,
		Port:             8080,
		AutoOpenPage:     true,
		ShowSpecialChars: true,
		ShowConsole:      false,
		StartOnBoot:      false,
	}
	configFile string
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	clients   = make(map[*websocket.Conn]bool)
	broadcast = make(chan string)
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
)

const (
	SW_HIDE = 0
)

func hideConsole() {
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, SW_HIDE)
	}
}

func main() {
	loadConfig()

	config.mu.RLock()
	showConsole := config.ShowConsole
	config.mu.RUnlock()

	if !showConsole {
		hideConsole()
	}

	go startWebServer()

	// 启动系统托盘
	systray.Run(onReady, onExit)
}

func onReady() {
	systray.SetIcon(iconBytes)
	updateSystrayTitle(5) // 传递一个整数参数

	mOpenHome := systray.AddMenuItem("打开主页", "打开主页")
	mOpenConfig := systray.AddMenuItem("打开配置页", "打开配置页")
	mAbout := systray.AddMenuItem("关于", "查看 GitHub 页")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("退出", "退出程序")

	go func() {
		for {
			select {
			case <-mOpenHome.ClickedCh:
				config.mu.RLock()
				port := config.Port
				config.mu.RUnlock()
				open.Run(fmt.Sprintf("http://localhost:%d", port))
			case <-mOpenConfig.ClickedCh:
				config.mu.RLock()
				port := config.Port
				config.mu.RUnlock()
				open.Run(fmt.Sprintf("http://localhost:%d/config", port))
			case <-mAbout.ClickedCh:
				open.Run("https://github.com/ij369/scanners-go")
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()

	fmt.Println("开始监听键盘输入...")
	fmt.Println("请访问 http://localhost:8080 进行配置")

	keyboardHook, _, _ = procSetWindowsHookEx.Call(
		WH_KEYBOARD_LL,
		syscall.NewCallback(hookCallback),
		0,
		0,
	)
	defer procUnhookWindowsHookEx.Call(keyboardHook)

	var msg MSG
	for {
		ret, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if ret == 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func onExit() {
	// 清理资源
	procUnhookWindowsHookEx.Call(keyboardHook)
}

func hookCallback(nCode int, wparam, lparam uintptr) uintptr {
	if nCode >= 0 {
		kbdstruct := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lparam))
		vkCode := kbdstruct.VkCode

		config.mu.RLock()
		showSpecialChars := config.ShowSpecialChars
		config.mu.RUnlock()

		switch wparam {
		case WM_KEYDOWN, WM_SYSKEYDOWN:
			now := time.Now()

			config.mu.RLock()
			resetInterval := time.Duration(config.ResetInterval) * time.Millisecond
			config.mu.RUnlock()

			if now.Sub(lastKeyTime) > resetInterval {
				input.Reset()
			}
			lastKeyTime = now

			switch vkCode {
			case VK_RETURN:
				if input.Len() > 0 {
					go sendData(input.String())
					fmt.Printf("发送数据: %s\n", input.String())
					input.Reset()
				}
			case VK_SHIFT, VK_LSHIFT, VK_RSHIFT:
				if vkCode == VK_LSHIFT {
					leftShiftPressed = true
					if showSpecialChars {
						input.WriteString("[LSHIFT]")
					}
				} else if vkCode == VK_RSHIFT {
					rightShiftPressed = true
					if showSpecialChars {
						input.WriteString("[RSHIFT]")
					}
				} else {
					leftShiftPressed = true
					rightShiftPressed = true
					if showSpecialChars {
						input.WriteString("[SHIFT]")
					}
				}
			case VK_TAB:
				if showSpecialChars {
					input.WriteString("[TAB]")
				}
			case VK_CAPITAL:
				capsLockOn = !capsLockOn
			default:
				char := getChar(vkCode, leftShiftPressed || rightShiftPressed, capsLockOn)
				if char != 0 {
					input.WriteRune(char)
				}
			}
		case WM_KEYUP, WM_SYSKEYUP:
			switch vkCode {
			case VK_SHIFT, VK_LSHIFT, VK_RSHIFT:
				if vkCode == VK_LSHIFT {
					leftShiftPressed = false
					if showSpecialChars {
						input.WriteString("[/LSHIFT]")
					}
				} else if vkCode == VK_RSHIFT {
					rightShiftPressed = false
					if showSpecialChars {
						input.WriteString("[/RSHIFT]")
					}
				} else {
					leftShiftPressed = false
					rightShiftPressed = false
					if showSpecialChars {
						input.WriteString("[/SHIFT]")
					}
				}
			}
		}
	}
	ret, _, _ := procCallNextHookEx.Call(keyboardHook, uintptr(nCode), wparam, lparam)
	return ret
}

func getChar(vkCode uint32, shiftPressed, capsLock bool) rune {
	// 处理特殊字符
	if shiftPressed {
		return getShiftChar(vkCode)
	}

	// 基本字符映射
	char := rune(mapVirtualKey(vkCode))

	// 处理字母
	if char >= 'A' && char <= 'Z' {
		// 默认为小写
		char += 32

		// 如果 Caps Lock 开启，则使用大写
		if capsLock {
			char -= 32
		}
	}

	return char
}

func getShiftChar(vkCode uint32) rune {
	shiftMap := map[uint32]rune{
		'0': ')', '1': '!', '2': '@', '3': '#', '4': '$', '5': '%',
		'6': '^', '7': '&', '8': '*', '9': '(',
		0xBD: '_', // -
		0xBB: '+', // =
		0xDB: '{', // [
		0xDD: '}', // ]
		0xDC: '|', // \
		0xBA: ':', // ;
		0xDE: '"', // '
		0xBC: '<', // ,
		0xBE: '>', // .
		0xBF: '?', // /
		0xC0: '~', // `
	}

	if char, ok := shiftMap[vkCode]; ok {
		return char
	}

	// 如果不在映射表中，返回大写字母
	return rune(mapVirtualKey(vkCode))
}

// 将虚拟键码映射到实际字符
func mapVirtualKey(vkCode uint32) uint16 {
	ret, _, _ := syscall.NewLazyDLL("user32.dll").NewProc("MapVirtualKeyW").Call(
		uintptr(vkCode),
		uintptr(2), // MAPVK_VK_TO_CHAR
	)
	return uint16(ret)
}

func sendData(data string) {
	config.mu.RLock()
	url := config.ForwardURL
	config.mu.RUnlock()

	jsonStr := []byte(fmt.Sprintf(`{"data":"%s"}`, data))

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonStr))
	if err != nil {
		fmt.Println("发送数据失败:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Println("数据发送成功，状态码:", resp.StatusCode)

	// 广播扫码结果
	broadcast <- data
}

func startWebServer() {
	// 主页路由
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			content, err := staticFiles.ReadFile("static/index.html")
			if err != nil {
				http.Error(w, "Home page not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.Write(content)
			return
		}

		// 处理根目录下的其他文件
		filePath := strings.TrimPrefix(r.URL.Path, "/")
		content, err := staticFiles.ReadFile("static/" + filePath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// 设置 Content-Type
		contentType := getContentType(filePath)
		w.Header().Set("Content-Type", contentType)
		w.Write(content)
	})

	// 配置页面路由
	http.HandleFunc("/config/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/config/" {
			content, err := staticFiles.ReadFile("static/config/index.html")
			if err != nil {
				http.Error(w, "Config page not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.Write(content)
			return
		}

		// 处理 /config/ 下的其他文件
		filePath := strings.TrimPrefix(r.URL.Path, "/config/")
		content, err := staticFiles.ReadFile("static/config/" + filePath)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		contentType := getContentType(filePath)
		w.Header().Set("Content-Type", contentType)
		w.Write(content)
	})

	// API 路由
	http.HandleFunc("/api/config", handleConfig)

	// WebSocket 路由
	http.HandleFunc("/ws", handleConnections)

	// 启动广播协程
	go handleBroadcasts()

	config.mu.RLock()
	initialPort := config.Port
	autoOpenPage := config.AutoOpenPage
	config.mu.RUnlock()

	maxAttempts := 5
	var server *http.Server
	var successPort int

	for attempt := 0; attempt < maxAttempts; attempt++ {
		port := initialPort + attempt
		addr := fmt.Sprintf(":%d", port)
		server = &http.Server{Addr: addr, Handler: nil}

		errChan := make(chan error, 1)
		go func() {
			fmt.Printf("尝试在端口 %d 启动 Web 服务器\n", port)
			errChan <- server.ListenAndServe()
		}()

		// 等待服务器启动或出错
		select {
		case err := <-errChan:
			if err != nil {
				log.Printf("在端口 %d 启动服务器失败: %v\n", port, err)
				continue // 尝试下一个端口
			}
		case <-time.After(500 * time.Millisecond):
			// 进行进一步检查服务器
			if isPortAvailable(port) {
				successPort = port
				break
			}
		}

		if successPort != 0 {
			break
		}
	}

	if successPort == 0 {
		log.Fatal("无法启动 Web 服务器")
	}

	fmt.Printf("Web 服务器成功启动在 http://localhost:%d\n", successPort)

	// 更新系统托盘标题
	updateSystrayTitle(successPort)

	if autoOpenPage {
		open.Run(fmt.Sprintf("http://localhost:%d/", successPort))
	}
}

func isPortAvailable(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Close()

	clients[ws] = true

	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			delete(clients, ws)
			break
		}
	}
}

func handleBroadcasts() {
	for {
		msg := <-broadcast
		for client := range clients {
			err := client.WriteMessage(websocket.TextMessage, []byte(msg))
			if err != nil {
				log.Printf("Websocket error: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		config.mu.RLock()
		json.NewEncoder(w).Encode(config)
		config.mu.RUnlock()
	} else if r.Method == "POST" {
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		config.mu.Lock()
		config.ForwardURL = newConfig.ForwardURL
		config.ResetInterval = newConfig.ResetInterval
		config.AutoOpenPage = newConfig.AutoOpenPage
		config.ShowSpecialChars = newConfig.ShowSpecialChars
		config.ShowConsole = newConfig.ShowConsole
		config.StartOnBoot = newConfig.StartOnBoot
		// 不更新端口，当前端口可能已经被调整
		config.mu.Unlock()
		saveConfig()

		// 如果启用或禁用了开机自启动，更新注册表
		updateStartOnBoot(newConfig.StartOnBoot)

		w.WriteHeader(http.StatusOK)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func updateStartOnBoot(enable bool) {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		log.Printf("无法打开注册表键: %v", err)
		return
	}
	defer key.Close()

	exePath, err := os.Executable()
	if err != nil {
		log.Printf("无法获取可执行文件路径: %v", err)
		return
	}

	// 删除所有旧的开机启动设置
	key.DeleteValue("ScannerApp")

	if enable {
		err = key.SetStringValue("ScannerApp", exePath)
		if err != nil {
			log.Printf("设置开机自启动失败: %v", err)
		}
	} else {
		log.Println("开机自启动已取消")
	}
}

func loadConfig() {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("读取配置文失败: %v", err)
		}
		return
	}

	config.mu.Lock()
	defer config.mu.Unlock()
	if err := json.Unmarshal(data, &config); err != nil {
		log.Printf("解析配置文件失败: %v", err)
	}
}

func saveConfig() {
	config.mu.RLock()
	data, err := json.MarshalIndent(config, "", "  ")
	config.mu.RUnlock()

	if err != nil {
		log.Printf("序列化配置失败: %v", err)
		return
	}

	err = ioutil.WriteFile(configFile, data, 0644)
	if err != nil {
		log.Printf("保存配置文件失败: %v", err)
	}
}

func init() {
	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	exPath := filepath.Dir(ex)
	configFile = filepath.Join(exPath, "scanner_config.json")
}

func updateSystrayTitle(port int) {
	systray.SetTitle(fmt.Sprintf("扫码枪程序:%d", port))
	systray.SetTooltip(fmt.Sprintf("扫码枪程序 (端口: %d)", port))
}

// 获取文件的 Content-Type
func getContentType(filePath string) string {
	ext := filepath.Ext(filePath)
	switch ext {
	case ".html":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".wav":
		return "audio/wav"
	case ".avif":
		return "image/avif"
	case ".webp":
		return "image/webp"
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	default:
		return "application/octet-stream"
	}
}
