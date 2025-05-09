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

        public DevSecOpsModel(ILogger<DevSecOpsModel> logger)
        {
            _logger = logger;
        }

        public void OnGet(string userInput)
        {
            _logger.LogInformation("DevSecOps page accessed.");

            // Log forging example
            if (!string.IsNullOrEmpty(userInput))
            {
                // Vulnerable code: directly logging user input
                _logger.LogInformation("User provided input: " + userInput);
            }

            // Regex DDoS (ReDoS) example
            string potentiallySlowRegex = @"^(\w+\s?)*$";
            string inputForRegex = "This is a test string that could be very long and cause issues ";
            try
            {
                // Simulate a long string by repeating the input
                string longInput = string.Concat(Enumerable.Repeat(inputForRegex, 10)); // Repeat 10 times for demo
                if (Regex.IsMatch(longInput, potentiallySlowRegex, RegexOptions.None, TimeSpan.FromSeconds(5)))
                {
                    _logger.LogInformation("Regex matched (potentially slow).");
                }
                else
                {
                    _logger.LogInformation("Regex did not match or timed out.");
                }
            }
            catch (RegexMatchTimeoutException ex)
            {
                _logger.LogError($"Regex operation timed out: {ex.Message}");
            }
            catch (Exception ex)
            {
                _logger.LogError($"An error occurred during regex processing: {ex.Message}");
            }
        }
    }
}
