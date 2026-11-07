
using System.Text.RegularExpressions;

string path = "data/auth.log";

List<Alert> alerts = AnalyzeAuthLog(path);

Console.WriteLine("\nIDS Alerts:");

foreach (Alert alert in alerts)
{
    Console.WriteLine($"Rule: {alert.Rule}");
    Console.WriteLine($"Line: {alert.Line}");
    Console.WriteLine($"IP Address: {alert.Ip}");
    Console.WriteLine($"Reason: {alert.Reason}");
    Console.WriteLine("-------------------------");
}

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
