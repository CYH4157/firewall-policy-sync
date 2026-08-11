// sg_firewall_from_excel.go
//
// 直接讀「計劃管理系統防火牆policy.xlsx」建立 Security Groups 並套用規則,
// 不需要使用者手動編輯 YAML —— 使用者只要改 Excel, 重跑這支程式就好。
//
// Excel 欄位需求 (第一個工作表, 有標題列):
//   Rule Name | Source Group + IPs | Destination Group + IPs | Port / Service(s)
//
// 分組規則 (從你們既有資料的命名慣例歸納):
//   - 同一個 Rule Name = 同一個 Security Group
//   - Rule Name 結尾 "in"  → ingress, remote_cidr 用該列的 Source IP
//   - Rule Name 結尾 "2ex" → egress,  remote_cidr 用該列的 Destination IP
//   - Port / Service(s) 格式例如 "HTTPS port:443", 沒標協定一律當 tcp
//
// 使用方式:
//   go run sg_firewall_from_excel.go --excel 計劃管理系統防火牆policy.xlsx --dry-run
//   go run sg_firewall_from_excel.go --excel 計劃管理系統防火牆policy.xlsx
//   go run sg_firewall_from_excel.go --excel 計劃管理系統防火牆policy.xlsx --sg-name planwebin

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"
)

// ─── 設定區 ─────────────────────────────────────────────────────
// 強烈建議改成從環境變數讀取, 不要把 Token 寫死在原始碼裡 commit 進版控。
// 範例:
//
//	export SG_BASE_URL="https://api.ai-trust.iic.nchc.org.tw"
//	export SG_PROJECT_ID="<your-project-id>"
//	export SG_TOKEN="ey..."
var (
	BaseURL   = getenvDefault("SG_BASE_URL", "https://api.ai-trust.iic.nchc.org.tw")
	ProjectID = getenvDefault("SG_PROJECT_ID", "")
	Token     = getenvDefault("SG_TOKEN", "")
)

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─── Excel 解析出的規則結構 ──────────────────────────────────────

type Rule struct {
	Label       string
	Direction   string // ingress / egress
	Protocol    string // tcp / udp
	PortMin     int
	PortMax     int
	RemoteCIDR  string
	Description string
}

type SecGroup struct {
	Name        string
	Description string
	Rules       []Rule
}

var portServiceRe = regexp.MustCompile(`(?i)^(.*?)\s*port\s*:\s*(\d+)\s*$`)

func cleanIP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ":")
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		s = s + "/32"
	}
	return s
}

func parsePortService(s string) (protocol string, port int, label string, err error) {
	s = strings.TrimSpace(s)
	m := portServiceRe.FindStringSubmatch(s)
	if m == nil {
		return "", 0, "", fmt.Errorf("無法解析 Port/Service 欄位: %q", s)
	}
	label = strings.TrimSpace(m[1])
	port, err = strconv.Atoi(m[2])
	if err != nil {
		return "", 0, "", err
	}
	protocol = "tcp"
	udpKeywords := []string{"dns-udp", "ntp", "snmp"} // 目前資料沒有, 保留擴充點
	lowerLabel := strings.ToLower(label)
	for _, k := range udpKeywords {
		if strings.Contains(lowerLabel, k) {
			protocol = "udp"
			break
		}
	}
	return protocol, port, label, nil
}

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
		direction := directionFor(ruleName)
		if direction == "" {
			fmt.Printf("  ⚠ 第 %d 列: Rule Name %q 結尾不是 in/2ex, 無法判斷方向, 已跳過\n", excelRowNo, ruleName)
			skipped++
			continue
		}

		src := cleanIP(get(row, "Source Group + IPs"))
		dst := cleanIP(get(row, "Destination Group + IPs"))
		protocol, port, label, err := parsePortService(get(row, "Port / Service(s)"))
		if err != nil {
			fmt.Printf("  ⚠ 第 %d 列解析失敗, 已跳過: %v\n", excelRowNo, err)
			skipped++
			continue
		}

		remoteCIDR := src
		if direction == "egress" {
			remoteCIDR = dst
		}

		rule := Rule{
			Label:       fmt.Sprintf("%s-%s-%d", ruleName, label, port),
			Direction:   direction,
			Protocol:    protocol,
			PortMin:     port,
			PortMax:     port,
			RemoteCIDR:  remoteCIDR,
			Description: fmt.Sprintf("%s (from excel row %d)", label, excelRowNo),
		}

		g, ok := groups[ruleName]
		if !ok {
			g = &SecGroup{Name: ruleName, Description: fmt.Sprintf("Imported from excel, group=%s", ruleName)}
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

// ─── SG / Rule 操作 (跟原本 sg_firewall.go 一致) ─────────────────

func createSG(name, desc string, dryRun bool) (string, error) {
	if dryRun {
		fmt.Printf("  [DRY-RUN] POST /security_groups  name=%q\n", name)
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
	fmt.Printf("    %-8s  %-4s  port %-6d  %s\n", rule.Direction, rule.Protocol, rule.PortMin, rule.RemoteCIDR)

	if dryRun {
		fmt.Printf("    [DRY-RUN] POST /security_groups/%s/rules\n", sgID)
		return nil
	}

	payload := map[string]any{
		"direction":      rule.Direction,
		"protocol":       rule.Protocol,
		"port_range_min": rule.PortMin,
		"port_range_max": rule.PortMax,
		"remote_cidr":    rule.RemoteCIDR,
		"description":    rule.Description,
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
	excelFile := flag.String("excel", "計劃管理系統防火牆policy.xlsx", "Excel 檔案路徑")
	dryRun := flag.Bool("dry-run", false, "不實際呼叫 API, 只印出計畫")
	sgName := flag.String("sg-name", "", "只處理指定名稱的 SG（空=全部）")
	flag.Parse()

	if ProjectID == "" || Token == "" {
		fmt.Fprintln(os.Stderr, "✗ 請先設定環境變數 SG_PROJECT_ID 與 SG_TOKEN (可選 SG_BASE_URL)")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║   Excel 防火牆政策 → OpenStack Security Group 匯入   ║")
	if *dryRun {
		fmt.Println("║              ★  DRY-RUN 模式（不呼叫 API）★         ║")
	}
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("  來源檔案：%s\n\n", *excelFile)

	secGroups, err := loadSecGroupsFromExcel(*excelFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ 讀取 Excel 失敗: %v\n", err)
		os.Exit(1)
	}

	existingSGs, err := fetchExistingSGNames()
	if err != nil {
		fmt.Printf("  ⚠ 查詢既有 Security Group 清單失敗 (%v), 改用 API 409 回應來判斷是否重複\n", err)
		existingSGs = map[string]string{}
	} else {
		fmt.Printf("  目前 OpenStack 上已有 %d 個 Security Group\n", len(existingSGs))
	}

	totalCreatedRules, totalFailedRules, totalSkippedSG := 0, 0, 0

	for _, sg := range secGroups {
		if *sgName != "" && sg.Name != *sgName {
			continue
		}

		fmt.Printf("──────────────────────────────────────────────────────\n")
		fmt.Printf("  SG: %s  (%d rules)\n", sg.Name, len(sg.Rules))

		var sgID string
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
		}

		for _, rule := range sg.Rules {
			if err := createRule(sgID, rule, *dryRun); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ 規則失敗 [%s]: %v\n", rule.Label, err)
				totalFailedRules++
			} else {
				totalCreatedRules++
			}
		}
	}

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════")
	fmt.Println("  匯入結果摘要")
	fmt.Println("══════════════════════════════════════════════════════")
	fmt.Printf("  沿用既有 SG : %d 個\n", totalSkippedSG)
	fmt.Printf("  成功規則    : %d 條 (含 API 回報已存在而跳過的)\n", totalCreatedRules)
	fmt.Printf("  失敗規則    : %d 條\n", totalFailedRules)
	if totalFailedRules == 0 {
		fmt.Println("  結果        : ✓ 全部完成")
	} else {
		fmt.Println("  結果        : ⚠ 部分失敗, 請檢查錯誤訊息")
		os.Exit(1)
	}
}
