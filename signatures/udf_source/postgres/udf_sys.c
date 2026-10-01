// UDF Source Code for PostgreSQL
// File: signatures/udf_source/postgres/udf_sys.c
// Compile: gcc -shared -fPIC -I$(pg_config --includedir-server) -o lib_pgudf_sys.so udf_sys.c

#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(sys_eval);
PG_FUNCTION_INFO_V1(sys_exec);

Datum sys_eval(PG_FUNCTION_ARGS) {
    char *cmd = text_to_cstring(PG_GETARG_TEXT_PP(0));
    FILE *fp;
    char buf[1024];
    char *output = malloc(1);
    output[0] = '\0';
    size_t output_len = 0;
    
    fp = popen(cmd, "r");
    if (!fp) {
        PG_RETURN_NULL();
    }
    
    while (fgets(buf, sizeof(buf), fp)) {
        size_t buf_len = strlen(buf);
        output = realloc(output, output_len + buf_len + 1);
        memcpy(output + output_len, buf, buf_len);
        output_len += buf_len;
        output[output_len] = '\0';
    }
    
    pclose(fp);
    
    text *result = cstring_to_text_with_len(output, output_len);
    free(output);
    PG_RETURN_TEXT_P(result);
}

Datum sys_exec(PG_FUNCTION_ARGS) {
    char *cmd = text_to_cstring(PG_GETARG_TEXT_PP(0));
    int result = system(cmd);
    PG_RETURN_INT32(result);
}