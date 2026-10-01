# UDF Source Code for MySQL

// File: signatures/udf_source/mysql/udf_sys.c
// Compile: gcc -shared -fPIC -I/usr/include/mysql -o lib_mysqludf_sys.so udf_sys.c

#include <stdlib.h>
#include <string.h>
#include <mysql.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#ifdef __WIN__
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

// sys_eval(cmd) - Returns command output as string
DLLEXPORT my_bool sys_eval_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
DLLEXPORT void sys_eval_deinit(UDF_INIT *initid);
DLLEXPORT char *sys_eval(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);

// sys_exec(cmd) - Returns exit code
DLLEXPORT my_bool sys_exec_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
DLLEXPORT void sys_exec_deinit(UDF_INIT *initid);
DLLEXPORT long long sys_exec(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error);

// sys_bineval(hex_binary) - Execute binary from hex
DLLEXPORT my_bool sys_bineval_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
DLLEXPORT void sys_bineval_deinit(UDF_INIT *initid);
DLLEXPORT char *sys_bineval(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error);

my_bool sys_eval_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
        strcpy(message, "sys_eval() requires one string argument");
        return 1;
    }
    initid->maybe_null = 1;
    return 0;
}

void sys_eval_deinit(UDF_INIT *initid) {}

char *sys_eval(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error) {
    FILE *fp;
    char cmd[1024];
    char buf[1024];
    char *output = malloc(1);
    output[0] = '\0';
    size_t output_len = 0;
    
    strncpy(cmd, args->args[0], sizeof(cmd) - 1);
    cmd[sizeof(cmd) - 1] = '\0';
    
    fp = popen(cmd, "r");
    if (!fp) {
        *is_null = 1;
        *error = 1;
        strcpy(message, "popen() failed");
        return NULL;
    }
    
    while (fgets(buf, sizeof(buf), fp)) {
        size_t buf_len = strlen(buf);
        output = realloc(output, output_len + buf_len + 1);
        memcpy(output + output_len, buf, buf_len);
        output_len += buf_len;
        output[output_len] = '\0';
    }
    
    pclose(fp);
    
    *length = output_len;
    return output;
}

my_bool sys_exec_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
        strcpy(message, "sys_exec() requires one string argument");
        return 1;
    }
    return 0;
}

void sys_exec_deinit(UDF_INIT *initid) {}

long long sys_exec(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error) {
    char cmd[1024];
    strncpy(cmd, args->args[0], sizeof(cmd) - 1);
    cmd[sizeof(cmd) - 1] = '\0';
    
    return system(cmd);
}

my_bool sys_bineval_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
    if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT) {
        strcpy(message, "sys_bineval() requires one string argument (hex)");
        return 1;
    }
    initid->maybe_null = 1;
    return 0;
}

void sys_bineval_deinit(UDF_INIT *initid) {}

char *sys_bineval(UDF_INIT *initid, UDF_ARGS *args, char *result, unsigned long *length, char *is_null, char *error) {
    // Decode hex, write to temp file, execute, capture output
    *is_null = 1;
    return NULL;
}