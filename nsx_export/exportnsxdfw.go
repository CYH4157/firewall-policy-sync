package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/xuri/excelize/v2"
)

// ─── 設定區（對應 Python 的 NSX_HOST / AUTH）────────────────────
// 帳號密碼請用環境變數帶入, 不要寫死在原始碼裡 commit 進版控:
//   NSX_HOST (可選, 預設 tanzan) / NSX_USER / NSX_PASS
// 例:
//   export NSX_HOST="https://vcftanzan-nsx.vcf-hybrid.nchc.org.tw/"
//   export NSX_USER="admin"
//   export NSX_PASS="******"
var (
	NSX_HOST = getenvDefault("NSX_HOST", "https://vcftanzan-nsx.vcf-hybrid.nchc.org.tw/")
	NSX_USER = getenvDefault("NSX_USER", "")
	NSX_PASS = getenvDefault("NSX_PASS", "")
)

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─── NSX API 回應結構 ────────────────────────────────────────────

type PolicyList struct {
	Results []Policy `json:"results"`
	Cursor  string   `json:"cursor"`
}

type Policy struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

type RuleList struct {
	Results []Rule `json:"results"`
	Cursor  string `json:"cursor"`
}

type Rule struct {
	DisplayName       string   `json:"display_name"`
	RuleID            int      `json:"rule_id"`
	SequenceNumber    int      `json:"sequence_number"`
	SourceGroups      []string `json:"source_groups"`
	DestinationGroups []string `json:"destination_groups"`
	Services          []string `json:"services"`
	Action            string   `json:"action"`
}

type GroupInfo struct {
	DisplayName string `json:"display_name"`
}

type IPList struct {
	Results []string `json:"results"`
}

type ServiceInfo struct {
	ServiceEntries []ServiceEntry `json:"service_entries"`
}

type ServiceEntry struct {
	DisplayName      string   `json:"display_name"`
	DestinationPorts []string `json:"destination_ports"`
	L4Protocol       string   `json:"l4_protocol"`
	Protocol         string   `json:"protocol"`
	ALG              string   `json:"alg"`
}

// ─── HTTP Client ─────────────────────────────────────────────────

type Client struct {
	http     *http.Client
	baseURL  string
	user     string
	password string
}

func newClient(baseURL, user, password string) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &Client{
		http:     &http.Client{Transport: tr},
		baseURL:  strings.TrimRight(baseURL, "/"),
		user:     user,
		password: password,
	}
}

func (c *Client) getJSON(path string, out interface{}) error {
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

// 帶分頁撈完所有 Policy
func (c *Client) getAllPolicies() ([]Policy, error) {
	var all []Policy
	cursor := ""
	for {
		path := "/policy/api/v1/infra/domains/default/security-policies"
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		var pl PolicyList
		if err := c.getJSON(path, &pl); err != nil {
			return nil, err
		}
		all = append(all, pl.Results...)
		if pl.Cursor == "" {
			break
		}
		cursor = pl.Cursor
	}
	return all, nil
}

// 帶分頁撈完所有 Rule
func (c *Client) getAllRules(policyID string) ([]Rule, error) {
	var all []Rule
	cursor := ""
	for {
		path := fmt.Sprintf(
			"/policy/api/v1/infra/domains/default/security-policies/%s/rules", policyID,
		)
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		var rl RuleList
		if err := c.getJSON(path, &rl); err != nil {
			return nil, err
		}
		all = append(all, rl.Results...)
		if rl.Cursor == "" {
			break
		}
		cursor = rl.Cursor
	}
	return all, nil
}

// ─── Group 詳情（名稱 + IP）────────────────────────────────────

func (c *Client) groupDetails(groupPath string) string {
	if strings.ToUpper(groupPath) == "ANY" {
		return "ANY"
	}

	var gi GroupInfo
	if err := c.getJSON("/policy/api/v1"+groupPath, &gi); err != nil {
		return groupPath
	}
	name := gi.DisplayName
	if name == "" {
		name = groupPath
	}

	var ipList IPList
	_ = c.getJSON("/policy/api/v1"+groupPath+"/members/ip-addresses", &ipList)

	if len(ipList.Results) == 0 {
		return name + " : No IPs"
	}
	return name + " : " + strings.Join(ipList.Results, ", ")
}

// ─── Service 詳情（Port / Protocol）────────────────────────────

func (c *Client) serviceDetails(servicePath string) string {
	if strings.ToUpper(servicePath) == "ANY" {
		return "ANY"
	}

	var si ServiceInfo
	if err := c.getJSON("/policy/api/v1"+servicePath, &si); err != nil {
		return servicePath
	}

	var parts []string
	for _, e := range si.ServiceEntries {
		var seg []string
		if len(e.DestinationPorts) > 0 {
			seg = append(seg, "Ports: "+strings.Join(e.DestinationPorts, ","))
		}
		if e.L4Protocol != "" {
			seg = append(seg, "Protocol: "+e.L4Protocol)
		}
		if e.Protocol != "" {
			seg = append(seg, "Protocol: "+e.Protocol)
		}
		if e.ALG != "" {
			seg = append(seg, "Algorithm: "+e.ALG)
		}
		if e.DisplayName != "" {
			seg = append(seg, "Name: "+e.DisplayName)
		}
		parts = append(parts, strings.Join(seg, " - "))
	}
	return strings.Join(parts, "\n")
}

// ─── 讀取輸入工具（可選，改成互動模式時用）──────────────────────

func prompt(label string) string {
	fmt.Print(label)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

// ─── Excel 欄位名稱（A, B, C, ...）──────────────────────────────

func colName(n int) string {
	name := ""
	for n > 0 {
		n--
		name = string(rune('A'+n%26)) + name
		n /= 26
	}
	return name
}

// ─── 主程式 ─────────────────────────────────────────────────────

func main() {
	fmt.Println("============================================================")
	fmt.Println("  NSX-T Firewall Rules Exporter (Go)")
	fmt.Println("============================================================")
	fmt.Printf("  Host : %s\n", NSX_HOST)
	fmt.Printf("  User : %s\n", NSX_USER)
	fmt.Println("============================================================")

	if NSX_USER == "" || NSX_PASS == "" {
		fmt.Fprintln(os.Stderr, "✗ 請先設定環境變數 NSX_USER 與 NSX_PASS (可選 NSX_HOST)")
		os.Exit(1)
	}

	client := newClient(NSX_HOST, NSX_USER, NSX_PASS)

	// ── 取得所有 Policy ─────────────────────────────────────
	fmt.Println("\n[1/2] Fetching Security Policies ...")
	policies, err := client.getAllPolicies()
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	fmt.Printf("  → %d policies found\n", len(policies))

	// ── 建立 Excel ──────────────────────────────────────────
	f := excelize.NewFile()
	defer f.Close()

	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"2F75B6"}, Pattern: 1},
		Alignment: &excelize.Alignment{WrapText: true, Vertical: "center"},
	})
	dataStyle, _ := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{WrapText: true, Vertical: "top"},
	})

	headers := []string{
		"Rule Name", "Rule ID", "Rule Sequence",
		"Source Group + IPs", "Destination Group + IPs", "Port / Service(s)",
		"Action",
	}
	colWidths := []float64{30, 12, 14, 50, 50, 45, 12}

	firstSheet := true

	// ── 逐 Policy 處理 ──────────────────────────────────────
	fmt.Println("\n[2/2] Processing rules ...")

	for _, policy := range policies {
		fmt.Printf("\n  Policy: %s\n", policy.DisplayName)

		rules, err := client.getAllRules(policy.ID)
		if err != nil {
			fmt.Printf("    WARNING: cannot fetch rules: %v\n", err)
			continue
		}
		fmt.Printf("    → %d rules\n", len(rules))

		// Sheet 名稱最多 31 字元
		sheetName := policy.DisplayName
		runes := []rune(sheetName)
		if len(runes) > 30 {
			sheetName = string(runes[:30])
		}

		// 第一個 sheet 直接改名，之後新增
		var sheet string
		if firstSheet {
			f.SetSheetName("Sheet1", sheetName)
			sheet = sheetName
			firstSheet = false
		} else {
			// excelize v2.8+ NewSheet 回傳 (int, error)
			_, err := f.NewSheet(sheetName)
			if err != nil {
				fmt.Printf("    WARNING: cannot create sheet: %v\n", err)
				continue
			}
			sheet = sheetName
		}

		// 標題列
		for ci, h := range headers {
			cell, _ := excelize.CoordinatesToCellName(ci+1, 1)
			_ = f.SetCellValue(sheet, cell, h)
			_ = f.SetCellStyle(sheet, cell, cell, titleStyle)
			_ = f.SetColWidth(sheet, colName(ci+1), colName(ci+1), colWidths[ci])
		}
		_ = f.SetRowHeight(sheet, 1, 22)

		// 資料列
		for ri, rule := range rules {
			row := ri + 2

			var srcParts []string
			for _, g := range rule.SourceGroups {
				srcParts = append(srcParts, client.groupDetails(g))
			}

			var dstParts []string
			for _, g := range rule.DestinationGroups {
				dstParts = append(dstParts, client.groupDetails(g))
			}

			var svcParts []string
			for _, s := range rule.Services {
				svcParts = append(svcParts, client.serviceDetails(s))
			}

			// Action 顯示（空值預設 ALLOW）
			action := strings.ToUpper(rule.Action)
			if action == "" {
				action = "ALLOW"
			}

			values := []interface{}{
				rule.DisplayName,
				rule.RuleID,
				rule.SequenceNumber,
				strings.Join(srcParts, "\n"),
				strings.Join(dstParts, "\n"),
				strings.Join(svcParts, "\n"),
				action,
			}

			for ci, v := range values {
				cell, _ := excelize.CoordinatesToCellName(ci+1, row)
				_ = f.SetCellValue(sheet, cell, v)
				_ = f.SetCellStyle(sheet, cell, cell, dataStyle)
			}

			// Action 欄位上色：ALLOW=綠、DROP/REJECT=紅、其他=橘
			actionCell, _ := excelize.CoordinatesToCellName(7, row)
			var actionColor string
			switch action {
			case "ALLOW":
				actionColor = "70AD47"
			case "DROP", "REJECT":
				actionColor = "FF0000"
			default:
				actionColor = "ED7D31"
			}
			actionStyle, _ := f.NewStyle(&excelize.Style{
				Font:      &excelize.Font{Bold: true, Color: "FFFFFF"},
				Fill:      excelize.Fill{Type: "pattern", Color: []string{actionColor}, Pattern: 1},
				Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
			})
			_ = f.SetCellStyle(sheet, actionCell, actionCell, actionStyle)

			_ = f.SetRowHeight(sheet, row, 60)

			fmt.Printf("    ✓ [%s] %s\n", action, rule.DisplayName)
		}
	}

	// ── 儲存 ────────────────────────────────────────────────
	outFile := "firewall-out.xlsx"
	if err := f.SaveAs(outFile); err != nil {
		fmt.Println("ERROR saving file:", err)
		os.Exit(1)
	}

	fmt.Printf("\n============================================================\n")
	fmt.Printf("  Export completed!  →  %s\n", outFile)
	fmt.Printf("============================================================\n")
}
