using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System;
using System.Text.RegularExpressions;

namespace webapp01.Pages
{
    public class DevSecOpsModel : PageModel
    {
        private readonly ILogger<DevSecOpsModel> _logger;

        [BindProperty(SupportsGet = true)]
        public string? UserInput { get; set; }

        [BindProperty]
        public string? RegexInput { get; set; }

        public string? LogForgingTestResult { get; private set; }
        public string? RegexTestResult { get; private set; }

        public DevSecOpsModel(ILogger<DevSecOpsModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            _logger.LogInformation("DevSecOps page visited at {Time}", DateTime.UtcNow);

            if (!string.IsNullOrEmpty(UserInput))
            {
                // Insecure Log Forging: UserInput is directly logged.
                // A malicious user could inject newline characters and fake log entries.
                // Example: userInput = "test%0AINFO:+User+logged+out"
                _logger.LogInformation("User input from query: " + UserInput); 
                LogForgingTestResult = $"Logged: 'User input from query: {UserInput}'. Check the application logs.";
            }
        }

        public IActionResult OnPostCheckRegex()
        {
            _logger.LogInformation("Checking regex pattern for input: {Input}", RegexInput);
            RegexTestResult = PerformRegexCheck(RegexInput ?? string.Empty);
            return Page();
        }

        private string PerformRegexCheck(string input)
        {
            // Insecure Regex (Potential ReDoS - Regular Expression Denial of Service)
            // The pattern (a+)+$ is an example of an "evil regex".
            // With inputs like "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" (many 'a's followed by '!')
            // it can cause catastrophic backtracking, leading to high CPU usage and denial of service.
            // GHAS Code Scanning can often detect such vulnerable regex patterns.
            string pattern = @"(a+)+$"; 
            string result;
            try
            {
                // It's good practice to set a timeout for regex operations.
                if (Regex.IsMatch(input, pattern, RegexOptions.None, TimeSpan.FromSeconds(2)))
                {
                    result = "Regex pattern matched.";
                    _logger.LogInformation(result);
                }
                else
                {
                    result = "Regex pattern did not match.";
                    _logger.LogInformation(result);
                }
            }
            catch (RegexMatchTimeoutException ex)
            {
                result = $"Regex operation timed out for input: '{input}'. This indicates a potential ReDoS vulnerability. Exception: {ex.Message}";
                _logger.LogWarning(result);
            }
            catch (Exception ex)
            {
                result = $"An error occurred during regex matching: {ex.Message}";
                _logger.LogError(ex, result);
            }
            return result;
        }
    }
}
