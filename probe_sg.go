// probe_sg.go —— 探測 ai-trust / OpenStack 安全群組 API 實際的欄位名稱。
//
// 用途: 抓一個已存在的 Security Group, 把它的規則原始 JSON 印出來,
//       這樣就能看到 API 到底用什麼欄位名存 port (port_range_min? port_min? ...)。
//
// 執行 (env 需先設好 SG_PROJECT_ID / SG_TOKEN, 可選 SG_BASE_URL):
//   go run probe_sg.go --sg-name planweb2ex
//   go run probe_sg.go                # 不指定就把所有 SG 都 dump 出來
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
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	base := env("SG_BASE_URL", "https://api.ai-trust.iic.nchc.org.tw")
	proj := env("SG_PROJECT_ID", "")
	token := env("SG_TOKEN", "")
	sgName := flag.String("sg-name", "", "只 dump 指定名稱的 SG（空=全部）")
	flag.Parse()

	if proj == "" || token == "" {
		fmt.Fprintln(os.Stderr, "✗ 請先設定 SG_PROJECT_ID 與 SG_TOKEN")
		os.Exit(1)
	}

	client := &http.Client{Timeout: 20 * time.Second}
	do := func(method, url string) []byte {
		req, _ := http.NewRequest(method, url, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ 連線失敗: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode >= 400 {
			fmt.Fprintf(os.Stderr, "✗ HTTP %d → %s\n", resp.StatusCode, string(data))
			os.Exit(1)
		}
		return data
	}

	pretty := func(raw []byte) string {
		var b bytes.Buffer
		if json.Indent(&b, raw, "", "  ") == nil {
			return b.String()
		}
		return string(raw)
	}

	listURL := fmt.Sprintf("%s/vps/api/v1/project/%s/security_groups", base, proj)
	listRaw := do("GET", listURL)

	var list struct {
		SecurityGroups []map[string]any `json:"security_groups"`
	}
	_ = json.Unmarshal(listRaw, &list)
	if len(list.SecurityGroups) == 0 {
		fmt.Println("=== 清單回傳原始 JSON (沒解析到 security_groups 陣列) ===")
		fmt.Println(pretty(listRaw))
		return
	}

	for _, sg := range list.SecurityGroups {
		name := fmt.Sprintf("%v", sg["name"])
		if *sgName != "" && name != *sgName {
			continue
		}
		id := fmt.Sprintf("%v", sg["id"])
		if id == "<nil>" {
			id = fmt.Sprintf("%v", sg["sg_id"])
		}
		fmt.Printf("\n========== SG %q (id=%s) 詳細規則 ==========\n", name, id)
		detailURL := fmt.Sprintf("%s/vps/api/v1/project/%s/security_groups/%s", base, proj, id)
		fmt.Println(pretty(do("GET", detailURL)))
	}
}
