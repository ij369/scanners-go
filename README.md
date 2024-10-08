# scanners-go 扫码枪转发器

本项目是一个用于转发扫码枪（条码枪）输入的工具，可以实现无焦点的情况下，将扫码结果转发到 http 服务器，基于 Golang 开发，适用于 Windows ，便于响应 Bar Code 或 Qr Code , 开箱即用。

## 特征

- 扫码枪输入内容不需要扫码枪有串口模式，兼容市面大多数种类扫码枪。
- 通过本项目可以后台无焦点实现监听。
- 转发到后端 http 服务器，支持执行外部命令。
- 使用 Golang 构建后的 exe 体积小，可执行文件约 10M 上下。

## 实现原理

1. 扫码枪属于 HID 设备，所有字符几乎能在同一瞬间按顺序输入完毕。
2. 通常扫码枪在输入完毕后会带回车键作为结束符。
3. 正则匹配内容。

本程序基于以上三点，实现扫码枪输入的准确识别，几乎不受扫码枪（扫描枪，条码枪）品牌限制。

##  使用指南
### 基本功能

通常默认就已经适合大多数情况使用了，你可以在 [配置页(./config/)](./config/) 里按照以下表格说明进行更精细的控制，配置页里可以实时生效修改，或者如果你熟悉 json 可以直接修改 **config.json** 文件并重新打开生效。

| 设置项                             | 使用说明                                                     | Key 值           |
| ---------------------------------- | ------------------------------------------------------------ | ---------------- |
| 转发接口 URL                       | 默认程序会在后台运行，将识别到的结果以 JSON 对象的格式 POST 给输入的后端 API | forwardURL       |
| 重置间隔 (毫秒)                    | 默认 500ms，可以调到更低，这个取决于扫码枪两个按键之间延迟，超过缓冲时间不会当成是扫码枪录入，会进行重置，用于区分人手和扫码枪，过滤掉人手输入。 | resetInterval    |
| 结束符后缀                         | 默认为回车键，即 CR，Enter 键，通常买的扫码枪，出厂都是带回车键作为结束键入的，有的扫码枪说明书可以自定义设置，如果和回车冲突，可以换 [TAB] 作为结尾标志来识别 | endSuffix        |
| 启动时打开主页                     | 打开后，在启动时会自动调用浏览器打开主页                     | autoOpenPage     |
| 显示特殊按键（如 [LSHIFT], [TAB]） | 开启后，你需要自己处理扫码枪的组合按键，扫码枪大小写通常是[LSHIFT]+字母，有的扫码枪说明书可以设置 | showSpecialChars |
| 显示控制台窗口                     | 如果你下载的是文件名里有 debug 的，启动时会显示黑色的控制台窗口，可用来调试，debug 版即使关闭也不影响，注意，debug 版如果不打开此项，启动时会瞬时闪一下控制台窗口，非 debug 的版本不会闪。 | showConsole      |
| 开机自动启动                       | 打开后，可以开机自启                                         | -                |
| 正则匹配                           | 可输入正则表达式，用来加强过滤。<br />例如：`ij369/scanners-go`可以写作`[a-z]{2}\d{3}/[a-z]{8}\-[a-z]{2}` 如果留空则会匹配所有内容 | outputRegex      |
| 执行动作                           | 开启后，可以在识别后触发额外外部命令，可以实现使用浏览器打开等操作 | actions          |

除了 http 转发结果到后端接口，如果是纯前端项目，可以监听本 origin 的 Websocket ，端口同应用端口，路径为`/ws`，可以打开 WebTools 参考如何连接。

### 执行动作

执行动作是指会在发送给后端结果的同时，执行一次外部命令，满足特殊需求。

| 设置项               | 说明                                                         | 举例                                                         | Key 值    |
| -------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | --------- |
| 命令或可执行文件路径 | 命令或完整的可执行文件路径                                   | 1. **调用 CMD**：`cmd` <br/>2. **可执行文件路径**: `C:\Program Files\Google\Chrome\Application\chrome.exe` | command   |
| 数据前缀             | 可以在扫码结果前加上特定字符串                               | `https://github.com/ij369/scanners-go?id=`                   | prefix    |
| 数据后缀             | 可以在扫码结果后加上特定字符串                               | `&lang=zh-CN`                                                | suffix    |
| 命令参数             | 可以每行一个参数。使用 `{data}` 表示扫码结果插入位置, `{data}` 包含前缀和后缀。也可以不包含 `{data}`. | 1. 执行 CMD 命令`/C echo {data} ｜ clip` <br>2. Chrome 参数启动 `--new-window {data}` | arguments |

占位符

| 占位符      | 作用                                                         |
| ----------- | ------------------------------------------------------------ |
| {timestamp} | 用于数据前缀，数据后缀，{timestamp} 的部分会替换成当前的 Unix 时间戳，可用于防止浏览器缓存，例如 `&t={timestamp}` . |
| {uuid}      | 用于数据前缀，数据后缀，作用同上，会替换成 4 代 UUID.        |
| {urlencode} | 用于数据前缀，数据后缀，可以使用两个 {urlencode} 包裹 URL 查询参数来实现编码，如果 {urlencode} 的个数为奇数，则最后一个的实现是将其后的部分进行 URI 编码。 |



------

如果本项目对你有帮助的话，欢迎 Fork / Star 本项目

项目地址

[𝐡𝐭𝐭𝐩𝐬://𝐠𝐢𝐭𝐡𝐮𝐛.𝐜𝐨𝐦/𝐢𝐣𝟑𝟔𝟗/𝐬𝐜𝐚𝐧𝐧𝐞𝐫𝐬-𝐠𝐨](https://github.com/ij369/scanners-go)