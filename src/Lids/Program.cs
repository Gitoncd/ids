
using System.Text.RegularExpressions;


// TASK B: SSH AUTHENTICATION LOG ANALYSIS


string authLogPath = "data/auth.log";

List<Alert> authAlerts = AnalyzeAuthLog(authLogPath);

Console.WriteLine("\n========== TASK B: SSH LOG ANALYSIS ==========");
Console.WriteLine("\nIDS Alerts:");

foreach (Alert alert in authAlerts)
{
    Console.WriteLine($"Rule: {alert.Rule}");
    Console.WriteLine($"Line: {alert.Line}");
    Console.WriteLine($"IP Address: {alert.Ip}");
    Console.WriteLine($"Reason: {alert.Reason}");
    Console.WriteLine("-------------------------");
}



// TASK C: WEB SERVER ACCESS LOG ANALYSIS


Console.WriteLine("\n========== TASK C: ACCESS LOG ANALYSIS ==========");

string accessLogPath = "data/access.log";

// Count HTTP 401 .
Dictionary<string, int> unauthorizedCounts = new Dictionary<string, int>();


Dictionary<string, int> unauthorizedAlertLines = new Dictionary<string, int>();


List<Alert> suspiciousAlerts = new List<Alert>();


Dictionary<int, int> statusCounts = new Dictionary<int, int>();

int lineNumber = 0;
int validLines = 0;
int malformedLines = 0;


foreach (string line in File.ReadLines(accessLogPath))
{
    lineNumber++;

    
    Match match = Regex.Match(
        line,
        @"^(?<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+""(?<request>.*?)""\s+(?<status>\d{3})\s+\d+$"
    );

    // If the line does not match the expected format, skip it.
    if (!match.Success)
    {
        malformedLines++;
        Console.WriteLine("Malformed line skipped: " + line);
        continue;
    }

    validLines++;

   
    string ip = match.Groups["ip"].Value;
    string request = match.Groups["request"].Value;
    int status = int.Parse(match.Groups["status"].Value);

    
if (statusCounts.ContainsKey(status))
{
    statusCounts[status]++;
}
else
{
    statusCounts[status] = 1;
}

    Console.WriteLine($"IP: {ip} | Request: {request} | Status: {status}");

    
    string decodedRequest = Uri.UnescapeDataString(request);


   

    if (Regex.IsMatch(decodedRequest, @"\bUNION\b", RegexOptions.IgnoreCase) &&
        Regex.IsMatch(decodedRequest, @"\bSELECT\b", RegexOptions.IgnoreCase))
    {
        suspiciousAlerts.Add(new Alert(
            "Possible SQL Injection",
            lineNumber,
            ip,
            "Request contains both UNION and SELECT."
        ));
    }


    

    if (decodedRequest.Contains("../") || decodedRequest.Contains(@"..\"))
    {
        suspiciousAlerts.Add(new Alert(
            "Possible Path Traversal",
            lineNumber,
            ip,
            "Request contains a directory traversal pattern."
        ));
    }


    

    if (decodedRequest.Contains("<script", StringComparison.OrdinalIgnoreCase))
    {
        suspiciousAlerts.Add(new Alert(
            "Possible XSS",
            lineNumber,
            ip,
            "Request contains a script tag."
        ));
    }


   

    if (decodedRequest.Contains("javascript:", StringComparison.OrdinalIgnoreCase))
    {
        suspiciousAlerts.Add(new Alert(
            "Possible JavaScript URL",
            lineNumber,
            ip,
            "Request contains javascript:."
        ));
    }


    

    if (status == 401)
    {
        if (unauthorizedCounts.ContainsKey(ip))
        {
            unauthorizedCounts[ip]++;
        }
        else
        {
            unauthorizedCounts[ip] = 1;
        }

        // Save the line where the IP reaches 3 responses.
        if (unauthorizedCounts[ip] == 3)
        {
            unauthorizedAlertLines[ip] = lineNumber;
        }
    }
}




Console.WriteLine("\nHTTP 401 Counts:");

foreach (var item in unauthorizedCounts)
{
    Console.WriteLine($"{item.Key}: {item.Value}");
}




Console.WriteLine("\nHTTP 401 Alerts:");

foreach (var item in unauthorizedCounts)
{
    if (item.Value >= 3)
    {
        Console.WriteLine("Rule: Multiple HTTP 401 responses");
        Console.WriteLine($"Line: {unauthorizedAlertLines[item.Key]}");
        Console.WriteLine($"IP Address: {item.Key}");
        Console.WriteLine($"Reason: This IP received {item.Value} HTTP 401 responses.");
        Console.WriteLine("-------------------------");
    }
}



Console.WriteLine("\nSuspicious Request Alerts:");

foreach (Alert alert in suspiciousAlerts)
{
    Console.WriteLine($"Rule: {alert.Rule}");
    Console.WriteLine($"Line: {alert.Line}");
    Console.WriteLine($"IP Address: {alert.Ip}");
    Console.WriteLine($"Reason: {alert.Reason}");
    Console.WriteLine("-------------------------");
}




Console.WriteLine("\nAccess Log Summary:");
Console.WriteLine($"Total lines: {lineNumber}");
Console.WriteLine($"Valid entries: {validLines}");
Console.WriteLine($"Malformed lines: {malformedLines}");

Console.WriteLine("\nHTTP Status Code Summary:");

foreach (var item in statusCounts)
{
    Console.WriteLine($"Status {item.Key}: {item.Value}");
}


// ==========================================
// TASK B METHOD: ANALYZE SSH AUTH LOG
// ==========================================

static List<Alert> AnalyzeAuthLog(string path)
{
    Dictionary<string, int> failedAttempts = new Dictionary<string, int>();

    Dictionary<string, int> alertLineNumbers = new Dictionary<string, int>();

    int lineNumber = 0;

    foreach (string line in File.ReadLines(path))
    {
        lineNumber++;

       
        if (string.IsNullOrWhiteSpace(line))
        {
            continue;
        }

       
        if (line.TrimStart().StartsWith("#"))
        {
            continue;
        }

        
        if (!line.Contains("Failed password"))
        {
            continue;
        }

        
        Match match = Regex.Match(
            line,
            @"\bfrom\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
        );

        if (match.Success)
        {
            string ip = match.Groups["ip"].Value;

            if (failedAttempts.ContainsKey(ip))
            {
                failedAttempts[ip]++;
            }
            else
            {
                failedAttempts[ip] = 1;
            }

            
            if (failedAttempts[ip] == 3)
            {
                alertLineNumbers[ip] = lineNumber;
            }
        }
    }

    List<Alert> alerts = new List<Alert>();

    // Generate an alert for IPs with 3 or more failed attempts.
    foreach (var item in failedAttempts)
    {
        if (item.Value >= 3)
        {
            alerts.Add(new Alert(
                "Multiple SSH failed logins",
                alertLineNumbers[item.Key],
                item.Key,
                $"This IP had {item.Value} failed SSH login attempts."
            ));
        }
    }

    return alerts;
}
