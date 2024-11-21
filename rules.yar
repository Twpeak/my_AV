rule SampleMalware
{
    meta:
        description = "Detects Sample Malware"  // 检测样本恶意软件
        author = "Your Name"                      // 作者信息
        date = "2024-11-20"                       // 创建日期
    strings:
        $a = "malicious_string"  // 替换为实际恶意字符串
        $b = { E2 34 A1 88 }      // 替换为实际的字节序列
    condition:
        any of them               // 条件：任一字符串匹配
}

rule SuspiciousFile
{
    meta:
        description = "Detects suspicious file types"  // 检测可疑文件类型
        author = "Your Name"                             // 作者信息
        date = "2024-11-20"                              // 创建日期
    strings:
        $a = "suspicious_keyword"  // 替换为可疑关键词
    condition:
        filesize < 100KB and $a      // 条件：文件小于100KB且包含可疑关键词
}

rule PEFile
{
    meta:
        description = "Detects PE files with suspicious characteristics"  // 检测具有可疑特征的PE文件
        author = "Your Name"                                              // 作者信息
        date = "2024-11-20"                                               // 创建日期
    condition:
        uint16(0) == 0x5A4D and // 检查文件是否为" MZ"头
        filesize < 500KB         // 条件：文件小于500KB
}

rule MaliciousFileTest
{
    meta:
        description = "Detects a test malicious file"  // 检测测试用恶意文件
        author = "Your Name"                             // 作者信息
        date = "2024-11-20"                              // 创建日期
    strings:
        $malicious_string = "malicious_string"          // 检测恶意字符串
        $another_string = "Execute shell commands"      // 检测可疑命令
        $payload = { E2 34 A1 88 }                       // 检测特定字节序列
    condition:
        any of them               // 条件：任一字符串匹配
}

rule RansomwareIndicator
{
    meta:
        description = "Detects indicators of ransomware activity"  // 检测勒索软件活动的指示
        author = "Your Name"                                        // 作者信息
        date = "2024-11-20"                                         // 创建日期
    strings:
        $s1 = "Encrypting your files"  // 检测勒索软件常见提示
        $s2 = "Payment required"        // 检测付款提示
        $s3 = "Your files have been encrypted" // 检测加密文件提示
    condition:
        any of them               // 条件：任一字符串匹配
}

rule SuspiciousProcess
{
    meta:
        description = "Detects execution of suspicious processes"  // 检测可疑进程的执行
        author = "Your Name"                                        // 作者信息
        date = "2024-11-20"                                         // 创建日期
    strings:
        $s1 = "cmd.exe /c"             // 检测通过cmd执行的命令
        $s2 = "powershell -ExecutionPolicy Bypass" // 检测可疑的PowerShell命令
    condition:
        any of them               // 条件：任一字符串匹配
}

rule MalwareDownload
{
    meta:
        description = "Detects URLs or strings associated with malware downloads"  // 检测与恶意下载相关的字符串或URL
        author = "Your Name"                                                    // 作者信息
        date = "2024-11-20"                                                     // 创建日期
    strings:
        $url1 = "http://malicious-site.com/download" // 检测恶意软件下载URL
        $url2 = "https://example.com/malware.exe"     // 检测潜在恶意文件的URL
    condition:
        any of them               // 条件：任一字符串匹配
}

rule PotentialKeylogger
{
    meta:
        description = "Detects potential keylogger behavior"  // 检测潜在的键盘记录器行为
        author = "Your Name"                                   // 作者信息
        date = "2024-11-20"                                    // 创建日期
    strings:
        $s1 = "record keystrokes"        // 检测记录按键的字符串
        $s2 = "send to remote server"     // 检测发送数据到远程服务器的字符串
    condition:
        any of them               // 条件：任一字符串匹配
}

rule SuspiciousEmail
{
    meta:
        description = "Detects suspicious email-related content"  // 检测可疑的电子邮件内容
        author = "Your Name"                                        // 作者信息
        date = "2024-11-20"                                         // 创建日期
    strings:
        $s1 = "Click here to win a prize!"          // 检测可疑的诱惑性链接
        $s2 = "Important: Immediate action required"  // 检测紧急通知的内容
    condition:
        any of them               // 条件：任一字符串匹配
}