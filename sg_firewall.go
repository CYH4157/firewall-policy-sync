// OpenStack Security Group 匯入腳本
//
// 從 firewall-mapping.yaml 讀取規則，建立 Security Groups 並套用規則
//
// 使用方式:
//   go run sg_firewall.go                        # 從 firewall-mapping.yaml 匯入全部
//   go run sg_firewall.go --dry-run              # 不實際呼叫 API，只印出計畫
//   go run sg_firewall.go --file custom.yaml     # 指定其他 yaml 檔
//   go run sg_firewall.go --sg-name "MyGroup"    # 只匯入指定 SG 名稱
//   go run sg_firewall.go --cleanup              # 刪除所有由 yaml 建立的 SG

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ─── 設定區 ─────────────────────────────────────────────────────
// 憑證請用環境變數帶入, 不要寫死在原始碼裡 commit 進版控:
//   SG_BASE_URL / SG_PROJECT_ID / SG_TOKEN
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

// ─── YAML 輸入結構（對應 exportnsxdfw.go 的輸出）────────────────

type YAMLInput struct {
	GeneratedFrom  string         `yaml:"generated_from"`
	SecurityGroups []YAMLSecGroup `yaml:"security_groups"`
}

type YAMLSecGroup struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Rules       []YAMLRule `yaml:"rules"`
	Skipped     []string   `yaml:"skipped_rules"`
}

type YAMLRule struct {
	Label       string  `yaml:"label"`
	Direction   string  `yaml:"direction"`
	Protocol    *string `yaml:"protocol"`
	PortMin     *int    `yaml:"port_min"`
	PortMax     *int    `yaml:"port_max"`
	RemoteCIDR  string  `yaml:"remote_cidr"`
	Description string  `yaml:"description"`
	NSXAction   string  `yaml:"nsx_action"`
}

// ─── HTTP Client ─────────────────────────────────────────────────

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

// ─── SG 操作 ─────────────────────────────────────────────────────

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
	return strVal(resp, "id", "sg_id"), nil
}

func deleteSG(sgID string, dryRun bool) error {
	if dryRun {
		fmt.Printf("  [DRY-RUN] DELETE /security_groups/%s\n", sgID)
		return nil
	}
	_, err := doRequest("DELETE", apiURL("security_groups", sgID), nil)
	return err
}

func createRule(sgID string, rule YAMLRule, dryRun bool) error {
	portStr := "all"
	if rule.PortMin != nil {
		portStr = fmt.Sprintf("%d", *rule.PortMin)
		if rule.PortMax != nil && *rule.PortMax != *rule.PortMin {
			portStr = fmt.Sprintf("%d-%d", *rule.PortMin, *rule.PortMax)
		}
	}
	proto := "all"
	if rule.Protocol != nil {
		proto = *rule.Protocol
	}
	fmt.Printf("    %-8s  %-5s  port %-10s  %s\n",
		rule.Direction, proto, portStr, rule.RemoteCIDR)

	if dryRun {
		fmt.Printf("    [DRY-RUN] POST /security_groups/%s/rules\n", sgID)
		return nil
	}

	payload := map[string]any{
		"direction":   rule.Direction,
		"description": rule.Description,
		"remote_cidr": rule.RemoteCIDR,
	}
	if rule.Protocol != nil {
		payload["protocol"] = *rule.Protocol
	}
	if rule.PortMin != nil {
		payload["port_range_min"] = *rule.PortMin
	}
	if rule.PortMax != nil {
		payload["port_range_max"] = *rule.PortMax
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
	yamlFile := flag.String("file", "firewall-mapping.yaml", "YAML 輸入檔路徑")
	dryRun := flag.Bool("dry-run", false, "不實際呼叫 API")
	cleanup := flag.Bool("cleanup", false, "刪除 yaml 中的所有 SG")
	sgName := flag.String("sg-name", "", "只處理指定名稱的 SG（空=全部）")
	flag.Parse()

	// 讀取 YAML
	raw, err := os.ReadFile(*yamlFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ 無法讀取 %s: %v\n", *yamlFile, err)
		os.Exit(1)
	}
	var input YAMLInput
	if err := yaml.Unmarshal(raw, &input); err != nil {
		fmt.Fprintf(os.Stderr, "✗ YAML 解析失敗: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║    NSX-T → OpenStack Security Group 匯入腳本         ║")
	if *dryRun {
		fmt.Println("║              ★  DRY-RUN 模式（不呼叫 API）★         ║")
	}
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("  來源：%s\n  SG 數量：%d\n\n", input.GeneratedFrom, len(input.SecurityGroups))

	totalCreated, totalFailed := 0, 0
	var createdSGIDs []string

	for _, sg := range input.SecurityGroups {
		// 過濾指定 SG
		if *sgName != "" && sg.Name != *sgName {
			continue
		}

		fmt.Printf("──────────────────────────────────────────────────────\n")
		fmt.Printf("  SG: %s  (%d rules)\n", sg.Name, len(sg.Rules))

		// 印出跳過的規則（DENY 等）
		if len(sg.Skipped) > 0 {
			fmt.Println("  ⚠  以下規則因 NSX-T 為 DENY，OpenStack SG 不支援，已跳過：")
			for _, s := range sg.Skipped {
				fmt.Printf("     - %s\n", s)
			}
		}

		if *cleanup {
			// Cleanup 模式：列出並嘗試刪除（需要已知 SG ID，這裡只做提示）
			fmt.Printf("  ℹ  Cleanup 模式請手動刪除 SG: %s\n", sg.Name)
			fmt.Println("     （或使用 --sg-id 搭配原始 sg_firewall.go 的 --cleanup）")
			continue
		}

		// 建立 SG
		sgID, err := createSG(sg.Name, sg.Description, *dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ 建立 SG 失敗: %v\n", err)
			totalFailed++
			continue
		}
		fmt.Printf("  ✓ SG 建立成功  id=%s\n", sgID)
		createdSGIDs = append(createdSGIDs, sgID)

		// 新增規則
		for _, rule := range sg.Rules {
			if err := createRule(sgID, rule, *dryRun); err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ 規則失敗 [%s]: %v\n", rule.Label, err)
				totalFailed++
			} else {
				totalCreated++
			}
		}
	}

	// 摘要
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════")
	fmt.Println("  匯入結果摘要")
	fmt.Println("══════════════════════════════════════════════════════")
	fmt.Printf("  成功規則 : %d 條\n", totalCreated)
	fmt.Printf("  失敗規則 : %d 條\n", totalFailed)
	if len(createdSGIDs) > 0 && !*dryRun {
		fmt.Println("  已建立 SG ID：")
		for _, id := range createdSGIDs {
			fmt.Printf("    - %s\n", id)
		}
	}
	if totalFailed == 0 {
		fmt.Println("  結果     : ✓ 全部完成")
	} else {
		fmt.Println("  結果     : ⚠ 部分失敗，請檢查錯誤訊息")
		os.Exit(1)
	}
}
