// sg_firewall_from_excel.go
//
// 直接讀「計劃管理系統防火牆policy.xlsx」建立 Security Groups 並套用規則,
// 不需要使用者手動編輯 YAML —— 使用者只要改 Excel, 重跑這支程式就好。
//
// Excel 欄位需求 (第一個工作表, 有標題列):
//   Rule Name | Source Group + IPs | Destination Group + IPs | Port / Service(s) | 方向
//   ("方向" 為選填欄; 沒有這欄時, 會退回用 Rule Name 結尾判斷方向)
//
// 分組規則 (從你們既有資料的命名慣例歸納):
//   - 同一個 Rule Name = 同一個 Security Group
//   - 方向優先讀「方向」欄 (ingress / egress); 沒填才退回看 Rule Name 結尾:
//       Rule Name 結尾 "in"  → ingress
//       Rule Name 結尾 "2ex" → egress
//   - ingress → remote_cidr 用該列的 Source IP
//   - egress  → remote_cidr 用該列的 Destination IP
//   - Port / Service(s) 兩種格式都吃:
//       純數字,        例如 "443"
//       服務名+port,   例如 "HTTPS port:443"
//     沒標協定一律當 tcp (常見服務會自動補上易讀名稱, 如 443→HTTPS)
//
// 使用方式:
//   go run sg_firewall_from_excel.go --excel 計劃管理系統防火牆policy.xlsx --dry-run
//   go run sg_firewall_from_excel.go --excel 計劃管理系統防火牆policy.xlsx
//   go run sg_firewall_from_excel.go --excel 計劃管理系統防火牆policy.xlsx --sg-name planwebin

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"
	"gopkg.in/yaml.v3"
)

// ─── 設定區 ─────────────────────────────────────────────────────
// 憑證來源優先序: 環境變數 > config.yaml > 空值。
// 使用者版本請把 BaseURL / ProjectID / Token 填在 exe 旁邊的 config.yaml,
// 不要把 Token 寫死在原始碼裡 commit 進版控。
var (
	BaseURL   = getenvDefault("SG_BASE_URL", "")
	ProjectID = getenvDefault("SG_PROJECT_ID", "")
	Token     = getenvDefault("SG_TOKEN", "")
)

const defaultBaseURL = "https://api.ai-trust.iic.nchc.org.tw"

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// FileConfig 對應 config.yaml 的內容。
type FileConfig struct {
	BaseURL   string `yaml:"base_url"`
	ProjectID string `yaml:"project_id"`
	Token     string `yaml:"token"`
	Excel     string `yaml:"excel"`
}

// configSearchPaths 依序找設定檔: exe 所在目錄 → 目前工作目錄。
// 這樣使用者直接雙擊 exe (工作目錄可能是別處) 也找得到旁邊的 config.yaml。
func configSearchPaths() []string {
	var paths []string
	if exe, err := os.Executable(); err == nil {
		paths = append(paths, filepath.Join(filepath.Dir(exe), "config.yaml"))
	}
	paths = append(paths, "config.yaml")
	return paths
}

// loadConfig 讀第一個找得到的 config.yaml; 找不到就回空設定 (不算錯,
// 因為使用者也可能改用環境變數)。
func loadConfig() FileConfig {
	var cfg FileConfig
	seen := map[string]bool{}
	for _, p := range configSearchPaths() {
		if seen[p] {
			continue
		}
		seen[p] = true
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "⚠ 設定檔 %s 格式有誤: %v\n", p, err)
			continue
		}
		fmt.Printf("  讀取設定檔: %s\n", p)
		return cfg
	}
	return cfg
}

// cleanConfigValue 去掉前後空白; 若還是範本裡的佔位字串 (開頭「請填入」),
// 就視為未填、回空字串, 避免拿假值去打 API。
func cleanConfigValue(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "請填入") {
		return ""
	}
	return s
}

// applyConfig 把 config.yaml 的值套進全域設定, 但環境變數優先 (已經有值就不覆蓋)。
func applyConfig(cfg FileConfig) {
	if ProjectID == "" {
		ProjectID = cleanConfigValue(cfg.ProjectID)
	}
	if Token == "" {
		Token = cleanConfigValue(cfg.Token)
	}
	if BaseURL == "" {
		BaseURL = cleanConfigValue(cfg.BaseURL)
	}
	if BaseURL == "" {
		BaseURL = defaultBaseURL
	}
}

// ─── Excel 解析出的規則結構 ──────────────────────────────────────

type Rule struct {
	Key         string // 穩定識別碼, 只跟 direction/protocol/port/remote_cidr 有關, 不受 excel 列順序影響
	Label       string
	Direction   string // ingress / egress
	Protocol    string // tcp / udp
	PortMin     int
	PortMax     int
	PortSpec    string // 送給 ai-trust API 的 port 值: 單一 port "443"; 範圍 "443:478"
	RemoteCIDR  string
	Description string
}

type SecGroup struct {
	Name        string
	Description string
	Rules       []Rule
}

var portServiceRe = regexp.MustCompile(`(?i)^(.*?)\s*port\s*:\s*(\d+)\s*$`)

// 所有由這支工具建立的規則, description 都會帶這個標記 + 穩定 key,
// 用來在下次執行時辨認「這是我建的」、以及偵測 excel 裡已經刪掉、但 OpenStack 上還留著的孤兒規則。
const managedMarkerPrefix = "[xlsx-managed:"

var managedMarkerRe = regexp.MustCompile(`\[xlsx-managed:([a-f0-9]{12})\]`)

// ruleKey 只用「規則的本質內容」算 hash (方向/協定/port/remote_cidr),
// 不包含 excel 列號或 label, 這樣即使使用者在 excel 裡插入/刪除/搬動列,
// 同一條規則永遠對到同一把 key。
func ruleKey(direction, protocol string, portMin, portMax int, remoteCIDR string) string {
	raw := fmt.Sprintf("%s|%s|%d|%d|%s", direction, protocol, portMin, portMax, remoteCIDR)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:12]
}

func extractManagedKey(description string) (string, bool) {
	m := managedMarkerRe.FindStringSubmatch(description)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func cleanIP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ":")
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		s = s + "/32"
	}
	return s
}

// 常見 port → 易讀服務名, 只用來讓 description / label 好認, 不影響實際規則。
var wellKnownPorts = map[int]string{
	22:   "SSH",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	443:  "HTTPS",
	3389: "RDP",
}

// portRangeRe 匹配純數字的 port 範圍, 例如 "443:478" 或 "443-478"。
var portRangeRe = regexp.MustCompile(`^(\d+)\s*[:\-]\s*(\d+)$`)

// buildPortSpec 依 min/max 組出要送 API 的 port 字串:
//   - 單一 port (min == max) → "443"
//   - 範圍     (min != max) → "443:478"
func buildPortSpec(portMin, portMax int) string {
	if portMin == portMax {
		return strconv.Itoa(portMin)
	}
	return fmt.Sprintf("%d:%d", portMin, portMax)
}

// parsePortService 解析 Excel 的 Port/Service 欄, 回傳:
//   portMin/portMax : 數值範圍 (單一 port 時兩者相同), 用來算穩定 key
//   portSpec        : 送給 ai-trust API `port` 欄位的字串 ("443" 或 "443:478")
//   label           : 易讀服務名 (查得到才有, 否則為空)
func parsePortService(s string) (protocol string, portMin, portMax int, portSpec, label string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, 0, "", "", fmt.Errorf("Port/Service 欄位為空")
	}

	// 格式一 (planweb_policy.xlsx): 純數字, 例如 "443"
	if n, e := strconv.Atoi(s); e == nil {
		label = wellKnownPorts[n] // 查不到就留空, 由呼叫端補預設 label
		return protocolFor(label), n, n, buildPortSpec(n, n), label, nil
	}

	// 格式二: port 範圍, 例如 "443:478" 或 "443-478"
	if m := portRangeRe.FindStringSubmatch(s); m != nil {
		lo, _ := strconv.Atoi(m[1])
		hi, _ := strconv.Atoi(m[2])
		if lo > hi {
			return "", 0, 0, "", "", fmt.Errorf("port 範圍起點大於終點: %q", s)
		}
		label = wellKnownPorts[lo]
		return protocolFor(label), lo, hi, buildPortSpec(lo, hi), label, nil
	}

	// 格式三 (計劃管理系統防火牆policy.xlsx): 服務名 + port, 例如 "HTTPS port:443"
	m := portServiceRe.FindStringSubmatch(s)
	if m == nil {
		return "", 0, 0, "", "", fmt.Errorf("無法解析 Port/Service 欄位: %q", s)
	}
	label = strings.TrimSpace(m[1])
	port, e := strconv.Atoi(m[2])
	if e != nil {
		return "", 0, 0, "", "", e
	}
	return protocolFor(label), port, port, buildPortSpec(port, port), label, nil
}

// protocolFor 依服務名推斷協定, 沒命中一律 tcp。
func protocolFor(label string) string {
	udpKeywords := []string{"dns-udp", "ntp", "snmp"} // 目前資料沒有, 保留擴充點
	lowerLabel := strings.ToLower(label)
	for _, k := range udpKeywords {
		if strings.Contains(lowerLabel, k) {
			return "udp"
		}
	}
	return "tcp"
}

// directionFromColumn 正規化「方向」欄的值。接受 ingress/egress、
// 以及常見的中文/簡寫寫法, 都對應回標準的 ingress / egress。
// 認不得就回空字串, 交給呼叫端退回用 Rule Name 判斷。
func directionFromColumn(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ingress", "in", "入", "進", "内", "內", "inbound":
		return "ingress"
	case "egress", "ex", "out", "出", "外", "outbound":
		return "egress"
	default:
		return ""
	}
}

// directionFor 是退路: 沒有「方向」欄或該欄留空時, 用 Rule Name 結尾判斷方向。
func directionFor(ruleName string) string {
	switch {
	case strings.HasSuffix(ruleName, "2ex"):
		return "egress"
	case strings.HasSuffix(ruleName, "in"):
		return "ingress"
	default:
		return ""
	}
}

// ─── 讀 Excel → 分組成 SecGroup 清單 ─────────────────────────────

func loadSecGroupsFromExcel(path string) ([]SecGroup, error) {
	fileName := filepath.Base(path)

	f, err := excelize.OpenFile(path)
	if err != nil {
		return nil, fmt.Errorf("開檔失敗: %w", err)
	}
	defer f.Close()

	sheet := f.GetSheetName(0)
	rows, err := f.GetRows(sheet)
	if err != nil {
		return nil, fmt.Errorf("讀取工作表失敗: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("Excel 沒有資料列")
	}

	header := rows[0]
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(h)] = i
	}
	required := []string{"Rule Name", "Source Group + IPs", "Destination Group + IPs", "Port / Service(s)"}
	for _, r := range required {
		if _, ok := col[r]; !ok {
			return nil, fmt.Errorf("Excel 缺少欄位: %q, 目前欄位: %v", r, header)
		}
	}

	get := func(row []string, key string) string {
		idx := col[key]
		if idx < len(row) {
			return row[idx]
		}
		return ""
	}

	order := []string{}
	groups := map[string]*SecGroup{}
	skipped := 0

	for i, row := range rows[1:] {
		excelRowNo := i + 2
		ruleName := strings.TrimSpace(get(row, "Rule Name"))
		if ruleName == "" {
			continue
		}
		// 方向優先讀「方向」欄 (ingress / egress); 該欄不存在或留空時,
		// 才退回用 Rule Name 結尾 (in / 2ex) 判斷。
		direction := ""
		if idx, ok := col["方向"]; ok && idx < len(row) {
			direction = directionFromColumn(row[idx])
		}
		if direction == "" {
			direction = directionFor(ruleName)
		}
		if direction == "" {
			fmt.Printf("  ⚠ 第 %d 列: 「方向」欄空白且 Rule Name %q 結尾不是 in/2ex, 無法判斷方向, 已跳過\n", excelRowNo, ruleName)
			skipped++
			continue
		}

		src := cleanIP(get(row, "Source Group + IPs"))
		dst := cleanIP(get(row, "Destination Group + IPs"))
		protocol, portMin, portMax, portSpec, label, err := parsePortService(get(row, "Port / Service(s)"))
		if err != nil {
			fmt.Printf("  ⚠ 第 %d 列解析失敗, 已跳過: %v\n", excelRowNo, err)
			skipped++
			continue
		}

		remoteCIDR := src
		if direction == "egress" {
			remoteCIDR = dst
		}

		key := ruleKey(direction, protocol, portMin, portMax, remoteCIDR)
		rule := Rule{
			Key:        key,
			Label:      fmt.Sprintf("%s-%s-%s", ruleName, label, portSpec),
			Direction:  direction,
			Protocol:   protocol,
			PortMin:    portMin,
			PortMax:    portMax,
			PortSpec:   portSpec,
			RemoteCIDR: remoteCIDR,
			Description: fmt.Sprintf("%s%s] %s (from %s, row %d)",
				managedMarkerPrefix, key, label, fileName, excelRowNo),
		}

		g, ok := groups[ruleName]
		if !ok {
			g = &SecGroup{Name: ruleName, Description: fmt.Sprintf(
				"[xlsx-managed] Created via API from %s, group=%s", fileName, ruleName)}
			groups[ruleName] = g
			order = append(order, ruleName)
		}
		g.Rules = append(g.Rules, rule)
	}

	result := make([]SecGroup, 0, len(order))
	totalRules := 0
	for _, name := range order {
		result = append(result, *groups[name])
		totalRules += len(groups[name].Rules)
	}

	fmt.Printf("  讀到 %d 個 Security Group, 共 %d 條規則, 跳過 %d 列\n", len(result), totalRules, skipped)
	return result, nil
}

// ─── HTTP Client (跟原本 sg_firewall.go 一致) ────────────────────

var httpClient = &http.Client{Timeout: 15 * time.Second}

func apiURL(parts ...string) string {
	path := ""
	for i, p := range parts {
		if i > 0 {
			path += "/"
		}
		path += p
	}
	return fmt.Sprintf("%s/vps/api/v1/project/%s/%s", BaseURL, ProjectID, path)
}

func doRequest(method, url string, body any) (map[string]any, error) {
	var bodyReader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, bodyReader)
	req.Header.Set("Authorization", "Bearer "+Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("連線失敗: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 409 {
		return map[string]any{"_already_exists": true}, nil
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d → %s", resp.StatusCode, string(data))
	}
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("解析 response 失敗: %w (raw: %s)", err, string(data))
	}
	return result, nil
}

func strVal(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return fmt.Sprintf("%v", v)
		}
	}
	return "(unknown)"
}

// ─── 既有 SG 名單 (拿來判斷「有沒有設定上去過」, 避免重複建立同名 SG) ──

func fetchExistingSGNames() (map[string]string, error) {
	// List Security Groups: GET /security_groups
	resp, err := doRequest("GET", apiURL("security_groups"), nil)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	// 回傳格式可能是 {"security_groups": [...]} 或直接是陣列包在某個 key 下,
	// 這裡盡量寬鬆解析, 找不到就當作沒有既有資料 (仍然可以繼續用 409 兜底判斷)。
	if list, ok := resp["security_groups"].([]any); ok {
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				name := strVal(m, "name")
				id := strVal(m, "id", "sg_id")
				if name != "(unknown)" {
					names[name] = id
				}
			}
		}
	}
	return names, nil
}

// fetchSGRules 撈某個 SG 目前在 OpenStack 上的所有規則 (假設 GET /security_groups/{sg-id}
// 回傳的 JSON 裡有 "rules" 陣列, 每個 rule 至少有 id 跟 description)。
func fetchSGRules(sgID string) ([]map[string]any, error) {
	resp, err := doRequest("GET", apiURL("security_groups", sgID), nil)
	if err != nil {
		return nil, err
	}
	if list, ok := resp["rules"].([]any); ok {
		out := make([]map[string]any, 0, len(list))
		for _, item := range list {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out, nil
	}
	return nil, nil
}

func deleteRule(sgID, ruleID string, dryRun bool) error {
	if dryRun {
		fmt.Printf("    [DRY-RUN] DELETE /security_groups/%s/rules/%s\n", sgID, ruleID)
		return nil
	}
	_, err := doRequest("DELETE", apiURL("security_groups", sgID, "rules", ruleID), nil)
	return err
}

// ─── SG / Rule 操作 (跟原本 sg_firewall.go 一致) ─────────────────

func createSG(name, desc string, dryRun bool) (string, error) {
	if dryRun {
		fmt.Printf("  [DRY-RUN] POST /security_groups  name=%q  description=%q\n", name, desc)
		return "dry-run-sg-id", nil
	}
	resp, err := doRequest("POST", apiURL("security_groups"), map[string]any{
		"name": name, "description": desc,
	})
	if err != nil {
		return "", err
	}
	if resp["_already_exists"] != nil {
		fmt.Printf("  ↩ Security Group %q 已存在, 沿用既有的 (需要手動確認 sg-id)\n", name)
	}
	return strVal(resp, "id", "sg_id"), nil
}

func createRule(sgID string, rule Rule, dryRun bool) error {
	fmt.Printf("    %-8s  %-4s  port %-9s  %s\n", rule.Direction, rule.Protocol, rule.PortSpec, rule.RemoteCIDR)

	if dryRun {
		fmt.Printf("    [DRY-RUN] POST /security_groups/%s/rules  port=%q description=%q\n", sgID, rule.PortSpec, rule.Description)
		return nil
	}

	payload := map[string]any{
		"direction":    rule.Direction,
		"protocol":     rule.Protocol,
		"port_min":     rule.PortMin,
		"port_max":     rule.PortMax,
		"network_type": "Ipv4",
		"remote_cidr":  rule.RemoteCIDR,
		"description":  rule.Description,
	}

	resp, err := doRequest("POST", apiURL("security_groups", sgID, "rules"), payload)
	if err != nil {
		return err
	}
	if resp["_already_exists"] != nil {
		fmt.Printf("    ↩ 規則已存在（跳過）\n")
	}
	return nil
}

// ─── 主程式 ─────────────────────────────────────────────────────

func main() {
	excelFile := flag.String("excel", "", "Excel 檔案路徑 (未指定時讀 config.yaml 的 excel, 再退回 planweb_policy.xlsx)")
	dryRun := flag.Bool("dry-run", false, "不實際呼叫 API, 只印出計畫")
	sgName := flag.String("sg-name", "", "只處理指定名稱的 SG（空=全部）")
	prune := flag.Bool("prune", false, "把 excel 裡已經刪掉、但 OpenStack 上還留著的規則(本工具建立的)一併刪除。不加這個只會印警告,不會真的刪")
	flag.Parse()

	// 讀 config.yaml 並套用 (環境變數優先; config 補空缺)。
	cfg := loadConfig()
	applyConfig(cfg)

	// Excel 路徑優先序: --excel 參數 > config.yaml 的 excel > 預設檔名。
	excelPath := *excelFile
	if excelPath == "" {
		excelPath = strings.TrimSpace(cfg.Excel)
	}
	if excelPath == "" {
		excelPath = "planweb_policy.xlsx"
	}

	if ProjectID == "" || Token == "" {
		fmt.Fprintln(os.Stderr, "✗ 找不到憑證。請在 exe 旁邊的 config.yaml 填好 project_id 與 token")
		fmt.Fprintln(os.Stderr, "  (進階使用者也可改用環境變數 SG_PROJECT_ID / SG_TOKEN / SG_BASE_URL)")
		exitPause(1)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║   Excel 防火牆政策 → OpenStack Security Group 匯入   ║")
	if *dryRun {
		fmt.Println("║              ★  DRY-RUN 模式（不呼叫 API）★         ║")
	}
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("  來源檔案：%s\n\n", excelPath)

	secGroups, err := loadSecGroupsFromExcel(excelPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ 讀取 Excel 失敗: %v\n", err)
		exitPause(1)
	}

	existingSGs, err := fetchExistingSGNames()
	if err != nil {
		fmt.Printf("  ⚠ 查詢既有 Security Group 清單失敗 (%v), 改用 API 409 回應來判斷是否重複\n", err)
		existingSGs = map[string]string{}
	} else {
		fmt.Printf("  目前 OpenStack 上已有 %d 個 Security Group\n", len(existingSGs))
	}

	totalCreatedRules, totalSkippedRules, totalFailedRules, totalSkippedSG := 0, 0, 0, 0
	totalOrphans, totalPruned := 0, 0

	for _, sg := range secGroups {
		if *sgName != "" && sg.Name != *sgName {
			continue
		}

		fmt.Printf("──────────────────────────────────────────────────────\n")
		fmt.Printf("  SG: %s  (%d rules)\n", sg.Name, len(sg.Rules))

		var sgID string
		isNewSG := false
		if existingID, ok := existingSGs[sg.Name]; ok {
			fmt.Printf("  ↩ Security Group %q 已經設定上去過 (id=%s), 沿用, 只補新的規則\n", sg.Name, existingID)
			sgID = existingID
			totalSkippedSG++
		} else {
			id, err := createSG(sg.Name, sg.Description, *dryRun)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ 建立 SG 失敗: %v\n", err)
				totalFailedRules += len(sg.Rules)
				continue
			}
			fmt.Printf("  ✓ SG 建立成功  id=%s\n", id)
			sgID = id
			isNewSG = true
		}

		desiredByKey := map[string]Rule{}
		for _, r := range sg.Rules {
			desiredByKey[r.Key] = r
		}

		// 撈這個 SG 目前在 OpenStack 上、由本工具建立的規則 (key -> rule id)。
		// 新建立的 SG (尤其 dry-run 時的假 id) 一定是空的, 不用查。
		existingManaged := map[string]string{}
		if !isNewSG || !*dryRun {
			existingRules, err := fetchSGRules(sgID)
			if err != nil {
				fmt.Printf("  ⚠ 查詢 %s 現有規則失敗 (%v), 這次略過孤兒規則偵測, 改用 API 409 兜底\n", sg.Name, err)
			}
			for _, m := range existingRules {
				desc := strVal(m, "description")
				if key, ok := extractManagedKey(desc); ok {
					existingManaged[key] = strVal(m, "id", "rule_id")
				}
			}
		}

		// 新增: excel 有、OpenStack 沒有的規則
		for key, rule := range desiredByKey {
			if _, ok := existingManaged[key]; ok {
				fmt.Printf("    ↩ 已存在（略過, key=%s）  %-8s %-4s port %-9s %s\n",
					key, rule.Direction, rule.Protocol, rule.PortSpec, rule.RemoteCIDR)
				totalSkippedRules++
				continue
			}
			if err := createRule(sgID, rule, *dryRun); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ 規則失敗 [%s]: %v\n", rule.Label, err)
				totalFailedRules++
			} else {
				totalCreatedRules++
			}
		}

		// 孤兒偵測: OpenStack 上有(本工具建的)、但 excel 裡已經沒有的規則
		for key, ruleID := range existingManaged {
			if _, ok := desiredByKey[key]; ok {
				continue
			}
			totalOrphans++
			fmt.Printf("  ⚠ 孤兒規則: excel 裡已經找不到這條了 (sg=%s, key=%s, id=%s)\n", sg.Name, key, ruleID)
			if *prune {
				if err := deleteRule(sgID, ruleID, *dryRun); err != nil {
					fmt.Fprintf(os.Stderr, "    ✗ 刪除失敗: %v\n", err)
				} else {
					fmt.Printf("    ✓ 已刪除\n")
					totalPruned++
				}
			} else {
				fmt.Printf("    (加 --prune 才會真的刪除, 目前只是提醒)\n")
			}
		}
	}

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════")
	fmt.Println("  匯入結果摘要")
	fmt.Println("══════════════════════════════════════════════════════")
	fmt.Printf("  沿用既有 SG   : %d 個\n", totalSkippedSG)
	fmt.Printf("  新增規則      : %d 條\n", totalCreatedRules)
	fmt.Printf("  已存在略過    : %d 條\n", totalSkippedRules)
	fmt.Printf("  失敗規則      : %d 條\n", totalFailedRules)
	fmt.Printf("  孤兒規則      : %d 條 (excel 已刪除但 OpenStack 還留著)\n", totalOrphans)
	if *prune {
		fmt.Printf("  已清除孤兒規則: %d 條\n", totalPruned)
	} else if totalOrphans > 0 {
		fmt.Println("  提示          : 加上 --prune 可以把上面列出的孤兒規則清掉")
	}
	if totalFailedRules == 0 {
		fmt.Println("  結果          : ✓ 全部完成")
		exitPause(0)
	} else {
		fmt.Println("  結果          : ⚠ 部分失敗, 請檢查錯誤訊息")
		exitPause(1)
	}
}

// exitPause 結束程式。預設會在關閉前倒數 10 秒, 讓雙擊執行的使用者看得到結果,
// 避免主控台視窗一閃即逝。從終端機/腳本執行時可設環境變數 SG_PAUSE=0 跳過等待。
func exitPause(code int) {
	if os.Getenv("SG_PAUSE") != "0" {
		for i := 10; i > 0; i-- {
			fmt.Printf("\r視窗將在 %2d 秒後自動關閉... (按 Ctrl+C 可立即關閉)", i)
			time.Sleep(1 * time.Second)
		}
		fmt.Println()
	}
	os.Exit(code)
}
