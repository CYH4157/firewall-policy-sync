package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
	"gopkg.in/yaml.v3"
)

// ─── 設定區 ─────────────────────────────────────────────────────
const (
	NSX_HOST = ""
	NSX_USER = ""
	NSX_PASS = ""
)

// ─── NSX-T API 結構 ──────────────────────────────────────────────

type PolicyList struct {
	Results []Policy `json:"results"`
	Cursor  string   `json:"cursor"`
}
type Policy struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}
type RuleList struct {
	Results []NSXRule `json:"results"`
	Cursor  string    `json:"cursor"`
}
type NSXRule struct {
	DisplayName       string   `json:"display_name"`
	RuleID            int      `json:"rule_id"`
	SequenceNumber    int      `json:"sequence_number"`
	SourceGroups      []string `json:"source_groups"`
	DestinationGroups []string `json:"destination_groups"`
	Services          []string `json:"services"`
	Action            string   `json:"action"`
	Direction         string   `json:"direction"` // IN / OUT / IN_OUT
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
}

// ─── YAML 輸出結構（OpenStack 格式）────────────────────────────

type YAMLOutput struct {
	GeneratedFrom  string         `yaml:"generated_from"`
	Note           string         `yaml:"note"`
	SecurityGroups []YAMLSecGroup `yaml:"security_groups"`
}

type YAMLSecGroup struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Rules       []YAMLRule `yaml:"rules"`
	Skipped     []string   `yaml:"skipped_rules,omitempty"`
}

type YAMLRule struct {
	Label       string  `yaml:"label"`
	Direction   string  `yaml:"direction"` // ingress / egress
	Protocol    *string `yaml:"protocol"`  // tcp / udp / icmp / null
	PortMin     *int    `yaml:"port_min,omitempty"`
	PortMax     *int    `yaml:"port_max,omitempty"`
	RemoteCIDR  string  `yaml:"remote_cidr"`
	Description string  `yaml:"description"`
	NSXAction   string  `yaml:"nsx_action"` // 原始 NSX-T action
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
		http:    &http.Client{Transport: tr},
		baseURL: strings.TrimRight(baseURL, "/"),
		user:    user, password: password,
	}
}

func (c *Client) getJSON(path string, out interface{}) error {
	req, _ := http.NewRequest("GET", c.baseURL+path, nil)
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

func (c *Client) getAll(path string, results interface{}) error {
	// results 需要是 *[]T，這裡用 generic approach via PolicyList/RuleList
	return nil
}

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

func (c *Client) getAllRules(policyID string) ([]NSXRule, error) {
	var all []NSXRule
	cursor := ""
	for {
		path := fmt.Sprintf("/policy/api/v1/infra/domains/default/security-policies/%s/rules", policyID)
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

func (c *Client) groupIPs(groupPath string) (string, []string) {
	if strings.ToUpper(groupPath) == "ANY" {
		return "ANY", []string{"0.0.0.0/0"}
	}
	var gi GroupInfo
	_ = c.getJSON("/policy/api/v1"+groupPath, &gi)
	name := gi.DisplayName
	if name == "" {
		name = groupPath
	}
	var ipList IPList
	_ = c.getJSON("/policy/api/v1"+groupPath+"/members/ip-addresses", &ipList)
	return name, ipList.Results
}

func (c *Client) serviceEntries(servicePath string) []ServiceEntry {
	if strings.ToUpper(servicePath) == "ANY" {
		return []ServiceEntry{{DisplayName: "ANY"}}
	}
	var si ServiceInfo
	_ = c.getJSON("/policy/api/v1"+servicePath, &si)
	return si.ServiceEntries
}

// ─── NSX-T → OpenStack Rule 轉換 ────────────────────────────────

func sp(s string) *string { return &s }
func ip(i int) *int       { return &i }

func parsePort(s string) (int, int) {
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		min, _ := strconv.Atoi(parts[0])
		max, _ := strconv.Atoi(parts[1])
		return min, max
	}
	v, _ := strconv.Atoi(s)
	return v, v
}

// nsxDirectionToOS：NSX-T direction → OpenStack direction 清單
// IN_OUT 拆成兩條
func nsxDirectionToOS(d string) []string {
	switch strings.ToUpper(d) {
	case "IN":
		return []string{"ingress"}
	case "OUT":
		return []string{"egress"}
	default: // IN_OUT 或空
		return []string{"ingress", "egress"}
	}
}

func mapRule(
	ruleName, action, nsxDirection string,
	sourceIPs, destIPs []string,
	entries []ServiceEntry,
) []YAMLRule {

	var rules []YAMLRule
	directions := nsxDirectionToOS(nsxDirection)

	for _, dir := range directions {
		// ingress：remote = source；egress：remote = destination
		var remoteCIDRs []string
		if dir == "ingress" {
			remoteCIDRs = sourceIPs
		} else {
			remoteCIDRs = destIPs
		}
		if len(remoteCIDRs) == 0 {
			remoteCIDRs = []string{"0.0.0.0/0"}
		}

		for _, cidr := range remoteCIDRs {
			// 純 IP 補 /32
			if cidr != "0.0.0.0/0" && !strings.Contains(cidr, "/") {
				cidr += "/32"
			}

			for _, entry := range entries {
				if entry.DisplayName == "ANY" {
					// ANY service = 全協定
					rules = append(rules, YAMLRule{
						Label:       fmt.Sprintf("%s [%s]", ruleName, dir),
						Direction:   dir,
						Protocol:    nil,
						RemoteCIDR:  cidr,
						Description: fmt.Sprintf("Migrated from NSX-T: %s", ruleName),
						NSXAction:   action,
					})
					continue
				}

				proto := strings.ToLower(entry.L4Protocol)
				if proto == "" {
					proto = strings.ToLower(entry.Protocol)
				}

				if len(entry.DestinationPorts) == 0 {
					rules = append(rules, YAMLRule{
						Label:       fmt.Sprintf("%s [%s]", ruleName, dir),
						Direction:   dir,
						Protocol:    sp(proto),
						RemoteCIDR:  cidr,
						Description: fmt.Sprintf("Migrated from NSX-T: %s / %s", ruleName, entry.DisplayName),
						NSXAction:   action,
					})
				} else {
					for _, portStr := range entry.DestinationPorts {
						min, max := parsePort(portStr)
						rules = append(rules, YAMLRule{
							Label:       fmt.Sprintf("%s [%s] port %s", ruleName, dir, portStr),
							Direction:   dir,
							Protocol:    sp(proto),
							PortMin:     ip(min),
							PortMax:     ip(max),
							RemoteCIDR:  cidr,
							Description: fmt.Sprintf("Migrated from NSX-T: %s / %s / port %s", ruleName, entry.DisplayName, portStr),
							NSXAction:   action,
						})
					}
				}
			}
		}
	}
	return rules
}

// ─── 欄位名稱工具 ────────────────────────────────────────────────

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
	fmt.Println("  Output: firewall-out.xlsx + firewall-mapping.yaml")
	fmt.Println("============================================================")
	fmt.Printf("  Host : %s\n  User : %s\n", NSX_HOST, NSX_USER)
	fmt.Println("============================================================")

	client := newClient(NSX_HOST, NSX_USER, NSX_PASS)

	fmt.Println("\n[1/3] Fetching Security Policies ...")
	policies, err := client.getAllPolicies()
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	fmt.Printf("  → %d policies found\n", len(policies))

	// Excel 初始化
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
	xlsHeaders := []string{
		"Rule Name", "Rule ID", "Sequence",
		"Source Group + IPs", "Destination Group + IPs",
		"Port / Service(s)", "Action", "Direction",
	}
	xlsWidths := []float64{30, 10, 10, 45, 45, 40, 12, 12}
	firstSheet := true

	// YAML 輸出
	yamlOut := YAMLOutput{
		GeneratedFrom: NSX_HOST,
		Note:          "DROP/REJECT 規則已標記 nsx_action，OpenStack SG 為 allowlist，請人工確認後決定是否排除。",
	}

	fmt.Println("\n[2/3] Processing policies and rules ...")

	for _, policy := range policies {
		fmt.Printf("\n  Policy: %s\n", policy.DisplayName)
		rules, err := client.getAllRules(policy.ID)
		if err != nil {
			fmt.Printf("    WARNING: %v\n", err)
			continue
		}
		fmt.Printf("    → %d rules\n", len(rules))

		sheetName := policy.DisplayName
		if len([]rune(sheetName)) > 30 {
			sheetName = string([]rune(sheetName)[:30])
		}
		var sheet string
		if firstSheet {
			f.SetSheetName("Sheet1", sheetName)
			sheet = sheetName
			firstSheet = false
		} else {
			_, err := f.NewSheet(sheetName)
			if err != nil {
				continue
			}
			sheet = sheetName
		}
		for ci, h := range xlsHeaders {
			cell, _ := excelize.CoordinatesToCellName(ci+1, 1)
			_ = f.SetCellValue(sheet, cell, h)
			_ = f.SetCellStyle(sheet, cell, cell, titleStyle)
			_ = f.SetColWidth(sheet, colName(ci+1), colName(ci+1), xlsWidths[ci])
		}
		_ = f.SetRowHeight(sheet, 1, 22)

		yamlSG := YAMLSecGroup{
			Name:        policy.DisplayName,
			Description: fmt.Sprintf("Migrated from NSX-T policy: %s", policy.ID),
		}

		for ri, rule := range rules {
			row := ri + 2
			action := strings.ToUpper(rule.Action)
			if action == "" {
				action = "ALLOW"
			}

			// 取 source group IPs
			var allSrcIPs []string
			var srcNames []string
			for _, g := range rule.SourceGroups {
				name, ips := client.groupIPs(g)
				srcNames = append(srcNames, fmt.Sprintf("%s: %s", name, strings.Join(ips, ", ")))
				allSrcIPs = append(allSrcIPs, ips...)
			}

			// 取 dest group IPs
			var allDstIPs []string
			var dstNames []string
			for _, g := range rule.DestinationGroups {
				name, ips := client.groupIPs(g)
				dstNames = append(dstNames, fmt.Sprintf("%s: %s", name, strings.Join(ips, ", ")))
				allDstIPs = append(allDstIPs, ips...)
			}

			// 取 services
			var allEntries []ServiceEntry
			var svcDesc []string
			for _, s := range rule.Services {
				entries := client.serviceEntries(s)
				allEntries = append(allEntries, entries...)
				for _, e := range entries {
					desc := e.DisplayName
					if len(e.DestinationPorts) > 0 {
						desc += " port:" + strings.Join(e.DestinationPorts, ",")
					}
					svcDesc = append(svcDesc, desc)
				}
			}
			if len(allEntries) == 0 {
				allEntries = []ServiceEntry{{DisplayName: "ANY"}}
			}

			// Excel 寫入
			actionColor := map[string]string{
				"ALLOW": "70AD47", "DROP": "FF0000", "REJECT": "FF0000",
			}
			color := actionColor[action]
			if color == "" {
				color = "ED7D31"
			}
			aStyle, _ := f.NewStyle(&excelize.Style{
				Font:      &excelize.Font{Bold: true, Color: "FFFFFF"},
				Fill:      excelize.Fill{Type: "pattern", Color: []string{color}, Pattern: 1},
				Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
			})
			xlsVals := []interface{}{
				rule.DisplayName, rule.RuleID, rule.SequenceNumber,
				strings.Join(srcNames, "\n"),
				strings.Join(dstNames, "\n"),
				strings.Join(svcDesc, "\n"),
				action, rule.Direction,
			}
			for ci, v := range xlsVals {
				cell, _ := excelize.CoordinatesToCellName(ci+1, row)
				_ = f.SetCellValue(sheet, cell, v)
				_ = f.SetCellStyle(sheet, cell, cell, dataStyle)
			}
			actionCell, _ := excelize.CoordinatesToCellName(7, row)
			_ = f.SetCellStyle(sheet, actionCell, actionCell, aStyle)
			_ = f.SetRowHeight(sheet, row, 60)

			// YAML mapping
			if action == "DROP" || action == "REJECT" {
				yamlSG.Skipped = append(yamlSG.Skipped,
					fmt.Sprintf("[%s] %s — OpenStack SG 不支援 deny，請人工處理", action, rule.DisplayName))
				fmt.Printf("    ⚠  [%s] %s → 加入 skipped\n", action, rule.DisplayName)
			} else {
				mapped := mapRule(rule.DisplayName, action, rule.Direction,
					allSrcIPs, allDstIPs, allEntries)
				yamlSG.Rules = append(yamlSG.Rules, mapped...)
				fmt.Printf("    ✓  [%s] %s → %d 條 OpenStack rule\n", action, rule.DisplayName, len(mapped))
			}
		}

		yamlOut.SecurityGroups = append(yamlOut.SecurityGroups, yamlSG)
	}

	// ── 儲存 Excel ───────────────────────────────────────────
	fmt.Println("\n[3/3] Saving files ...")
	if err := f.SaveAs("firewall-out.xlsx"); err != nil {
		fmt.Println("ERROR (xlsx):", err)
	} else {
		fmt.Println("  ✓ firewall-out.xlsx")
	}

	// ── 儲存 YAML ────────────────────────────────────────────
	yf, err := os.Create("firewall-mapping.yaml")
	if err != nil {
		fmt.Println("ERROR (yaml):", err)
	} else {
		enc := yaml.NewEncoder(yf)
		enc.SetIndent(2)
		_ = enc.Encode(yamlOut)
		yf.Close()
		fmt.Println("  ✓ firewall-mapping.yaml")
	}

	fmt.Println("\n============================================================")
	fmt.Println("  Done! 請先審閱 firewall-mapping.yaml 再執行 sg_firewall.go")
	fmt.Println("============================================================")
}
