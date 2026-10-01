package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Version   string
	BuildDate string
	Commit    string
	cfgFile   string
	logger    *zap.Logger
)

var rootCmd = &cobra.Command{
	Use:   "sqli",
	Short: "Chuỗi kiểm thử và khai thác SQL Injection",
	Long: `Tự động kiểm thử SQLi: phát hiện → vượt WAF → trích xuất → shell → duy trì → phá hủy.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initLogger()
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)
	
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "file cấu hình (mặc định: ./config/sqli.yaml)")
	rootCmd.PersistentFlags().StringP("output", "o", "json", "định dạng kết quả (json|csv|table)")
	rootCmd.PersistentFlags().Bool("verbose", false, "hiển thị log chi tiết")
	rootCmd.PersistentFlags().Bool("no-color", false, "tắt màu trong kết quả")
	
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("no-color", rootCmd.PersistentFlags().Lookup("no-color"))
	
	rootCmd.AddCommand(exploitCmd)
	rootCmd.AddCommand(detectCmd)
	rootCmd.AddCommand(dumpCmd)
	rootCmd.AddCommand(shellCmd)
	rootCmd.AddCommand(persistCmd)
	rootCmd.AddCommand(destructCmd)
	rootCmd.AddCommand(sessionCmd)
	rootCmd.AddCommand(tamperCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("sqli")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/home/hainx/Documents/SQLI-HAILAMDEV/config")
		viper.AddConfigPath("$HOME/.sqli")
		viper.AddConfigPath("/etc/sqli")
	}
	
	viper.SetEnvPrefix("SQLI")
	viper.AutomaticEnv()
	
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "Lỗi cấu hình: %v\n", err)
		}
	}
}

func initLogger() error {
	cfg := zap.NewProductionConfig()
	
	if viper.GetBool("verbose") {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	
	if viper.GetBool("no-color") {
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	} else {
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}
	
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	
	var err error
	logger, err = cfg.Build()
	return err
}

func Logger() *zap.Logger {
	if logger == nil {
		logger, _ = zap.NewProduction()
	}
	return logger
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "In thông tin phiên bản",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Phiên bản SQLI: %s\n", Version)
		fmt.Printf("Ngày build: %s\n", BuildDate)
		fmt.Printf("Commit: %s\n", Commit)
		fmt.Printf("Phiên bản Go: %s\n", runtime.Version())
		fmt.Printf("Hệ điều hành/kiến trúc: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Quản lý cấu hình",
}

var exploitCmd = &cobra.Command{
	Use:   "exploit",
	Short: "Chạy toàn bộ chuỗi kiểm thử",
	Long:  `Tự động phát hiện, kiểm tra WAF, trích xuất dữ liệu, mở shell, duy trì và phá hủy.`,
	RunE:  runExploit,
}

var detectCmd = &cobra.Command{
	Use:   "detect",
	Short: "Phát hiện điểm tiêm và DBMS",
	RunE:  runDetect,
}

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Trích xuất schema và dữ liệu cơ sở dữ liệu",
	RunE:  runDump,
}

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Mở OS shell thông qua tiêm UDF",
	RunE:  runShell,
}

var persistCmd = &cobra.Command{
	Use:   "persist",
	Short: "Thiết lập cơ chế duy trì trong cơ sở dữ liệu",
	RunE:  runPersist,
}

var destructCmd = &cobra.Command{
	Use:   "destruct",
	Short: "Thao tác phá hủy (DROP, TRUNCATE, CORRUPT, ENCRYPT)",
	RunE:  runDestruct,
}

var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Quản lý session",
}

var tamperCmd = &cobra.Command{
	Use:   "tamper",
	Short: "Script biến đổi payload để kiểm thử WAF",
}

func runExploit(cmd *cobra.Command, args []string) error {
	url, _ := cmd.Flags().GetString("url")
	data, _ := cmd.Flags().GetString("data")
	param, _ := cmd.Flags().GetString("param")
	headers, _ := cmd.Flags().GetStringArray("header")
	cookies, _ := cmd.Flags().GetStringArray("cookie")
	method, _ := cmd.Flags().GetString("method")
	auto, _ := cmd.Flags().GetBool("auto")
	fullPipeline, _ := cmd.Flags().GetBool("full-pipeline")
	destructMode, _ := cmd.Flags().GetString("destruct")
	threads, _ := cmd.Flags().GetInt("threads")
	tamperChain, _ := cmd.Flags().GetString("tamper")
	resume, _ := cmd.Flags().GetString("resume")
	
	if url == "" && resume == "" {
		return fmt.Errorf("bắt buộc có url hoặc --resume")
	}
	
	logger := Logger()
	logger.Info("Bắt đầu chuỗi kiểm thử",
		zap.String("url", url),
		zap.Bool("auto", auto),
		zap.Bool("full_pipeline", fullPipeline),
		zap.String("destruct", destructMode))
	
	engine := NewEngine()
	ctx := cmd.Context()
	
	var session *Session
	var err error
	
	if resume != "" {
		session, err = LoadSession(resume)
		if err != nil {
			return err
		}
		logger.Info("Đã khôi phục session", zap.String("id", session.ID))
	} else {
		session = NewSession(url, method, data, param, headers, cookies)
	}
	
	opts := EngineOptions{
		Auto:          auto,
		FullPipeline:  fullPipeline,
		DestructMode:  destructMode,
		Threads:       threads,
		TamperChain:   parseTamperChain(tamperChain),
	}
	
	result, err := engine.Run(ctx, session, opts)
	if err != nil {
		return err
	}
	
	return outputResult(result, cmd)
}

func runDetect(cmd *cobra.Command, args []string) error {
	url, _ := cmd.Flags().GetString("url")
	data, _ := cmd.Flags().GetString("data")
	param, _ := cmd.Flags().GetString("param")
	headers, _ := cmd.Flags().GetStringArray("header")
	cookies, _ := cmd.Flags().GetStringArray("cookie")
	method, _ := cmd.Flags().GetString("method")
	
	if url == "" {
		return fmt.Errorf("bắt buộc có url")
	}
	
	logger := Logger()
	logger.Info("Bắt đầu phát hiện", zap.String("url", url))
	
	detector := NewDetector()
	ctx := cmd.Context()
	
	session := NewSession(url, method, data, param, headers, cookies)
	result, err := detector.Detect(ctx, session)
	if err != nil {
		return err
	}
	
	return outputResult(result, cmd)
}

func runDump(cmd *cobra.Command, args []string) error {
	url, _ := cmd.Flags().GetString("url")
	resume, _ := cmd.Flags().GetString("resume")
	db, _ := cmd.Flags().GetString("db")
	table, _ := cmd.Flags().GetString("table")
	columns, _ := cmd.Flags().GetString("columns")
	where, _ := cmd.Flags().GetString("where")
	limit, _ := cmd.Flags().GetInt("limit")
	format, _ := cmd.Flags().GetString("format")
	
	if url == "" && resume == "" {
		return fmt.Errorf("bắt buộc có url hoặc --resume")
	}
	
	logger := Logger()
	logger.Info("Bắt đầu trích xuất dữ liệu", zap.String("url", url))
	
	dumper := NewDumper()
	ctx := cmd.Context()
	
	var session *Session
	if resume != "" {
		session, _ = LoadSession(resume)
	} else {
		data, _ := cmd.Flags().GetString("data")
		param, _ := cmd.Flags().GetString("param")
		headers, _ := cmd.Flags().GetStringArray("header")
		cookies, _ := cmd.Flags().GetStringArray("cookie")
		method, _ := cmd.Flags().GetString("method")
		session = NewSession(url, method, data, param, headers, cookies)
	}
	
	opts := DumpOptions{
		Database: db,
		Table:    table,
		Columns:  parseColumns(columns),
		Where:    where,
		Limit:    limit,
		Format:   format,
	}
	
	result, err := dumper.Dump(ctx, session, opts)
	if err != nil {
		return err
	}
	
	return outputResult(result, cmd)
}

func runShell(cmd *cobra.Command, args []string) error {
	url, _ := cmd.Flags().GetString("url")
	resume, _ := cmd.Flags().GetString("resume")
	command, _ := cmd.Flags().GetString("cmd")
	interactive, _ := cmd.Flags().GetBool("interactive")
	shellType, _ := cmd.Flags().GetString("type")
	
	if url == "" && resume == "" {
		return fmt.Errorf("bắt buộc có url hoặc --resume")
	}
	
	logger := Logger()
	logger.Info("Bắt đầu shell", zap.String("url", url), zap.String("type", shellType))
	
	shell := NewShell()
	ctx := cmd.Context()
	
	var session *Session
	if resume != "" {
		session, _ = LoadSession(resume)
	} else {
		data, _ := cmd.Flags().GetString("data")
		param, _ := cmd.Flags().GetString("param")
		headers, _ := cmd.Flags().GetStringArray("header")
		cookies, _ := cmd.Flags().GetStringArray("cookie")
		method, _ := cmd.Flags().GetString("method")
		session = NewSession(url, method, data, param, headers, cookies)
	}
	
	opts := ShellOptions{
		Command:     command,
		Interactive: interactive,
		Type:        shellType,
	}
	
	result, err := shell.Execute(ctx, session, opts)
	if err != nil {
		return err
	}
	
	return outputResult(result, cmd)
}

func runPersist(cmd *cobra.Command, args []string) error {
	url, _ := cmd.Flags().GetString("url")
	resume, _ := cmd.Flags().GetString("resume")
	methods, _ := cmd.Flags().GetStringArray("method")
	
	if url == "" && resume == "" {
		return fmt.Errorf("bắt buộc có url hoặc --resume")
	}
	
	logger := Logger()
	logger.Info("Bắt đầu thiết lập cơ chế duy trì", zap.String("url", url), zap.Strings("methods", methods))
	
	persist := NewPersistence()
	ctx := cmd.Context()
	
	var session *Session
	if resume != "" {
		session, _ = LoadSession(resume)
	} else {
		data, _ := cmd.Flags().GetString("data")
		param, _ := cmd.Flags().GetString("param")
		headers, _ := cmd.Flags().GetStringArray("header")
		cookies, _ := cmd.Flags().GetStringArray("cookie")
		method, _ := cmd.Flags().GetString("method")
		session = NewSession(url, method, data, param, headers, cookies)
	}
	
	opts := PersistOptions{
		Methods: methods,
	}
	
	result, err := persist.Establish(ctx, session, opts)
	if err != nil {
		return err
	}
	
	return outputResult(result, cmd)
}

func runDestruct(cmd *cobra.Command, args []string) error {
	url, _ := cmd.Flags().GetString("url")
	resume, _ := cmd.Flags().GetString("resume")
	mode, _ := cmd.Flags().GetString("mode")
	targetDB, _ := cmd.Flags().GetString("database")
	targetTable, _ := cmd.Flags().GetString("table")
	confirm, _ := cmd.Flags().GetBool("confirm")
	encryptKey, _ := cmd.Flags().GetString("encrypt-key")
	
	if url == "" && resume == "" {
		return fmt.Errorf("bắt buộc có url hoặc --resume")
	}
	
	if !confirm {
		return fmt.Errorf("thao tác phá hủy yêu cầu flag --confirm")
	}
	
	logger := Logger()
	logger.Warn("Bắt đầu thao tác PHÁ HỦY",
		zap.String("url", url),
		zap.String("mode", mode),
		zap.String("database", targetDB),
		zap.String("table", targetTable))
	
	destruct := NewDestructor()
	ctx := cmd.Context()
	
	var session *Session
	if resume != "" {
		session, _ = LoadSession(resume)
	} else {
		data, _ := cmd.Flags().GetString("data")
		param, _ := cmd.Flags().GetString("param")
		headers, _ := cmd.Flags().GetStringArray("header")
		cookies, _ := cmd.Flags().GetStringArray("cookie")
		method, _ := cmd.Flags().GetString("method")
		session = NewSession(url, method, data, param, headers, cookies)
	}
	
	opts := DestructOptions{
		Mode:         mode,
		Database:     targetDB,
		Table:        targetTable,
		EncryptKey:   encryptKey,
	}
	
	result, err := destruct.Execute(ctx, session, opts)
	if err != nil {
		return err
	}
	
	return outputResult(result, cmd)
}

func parseTamperChain(chain string) []string {
	if chain == "" {
		return []string{}
	}
	parts := strings.Split(chain, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func parseColumns(cols string) []string {
	if cols == "" {
		return []string{}
	}
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func outputResult(result interface{}, cmd *cobra.Command) error {
	format, _ := cmd.Flags().GetString("output")
	// TODO: định dạng kết quả theo loại output
	fmt.Printf("Kết quả: %+v\n", result)
	return nil
}
