using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;

namespace webapp01.Pages
{
    public class DevSecOpsModel : PageModel
    {
        private readonly ILogger<DevSecOpsModel> _logger;
        public string InsecureLogExample { get; private set; }
        public string InsecureRegexExample { get; private set; }

        public DevSecOpsModel(ILogger<DevSecOpsModel> logger)
        {
            _logger = logger;
        }

        public void OnGet()
        {
            // Insecure log forging example
            string userInput = "attacker\nInjectedLogEntry";
            _logger.LogInformation("User input: {UserInput}", userInput);
            InsecureLogExample = $"_logger.LogInformation(\"User input: {{UserInput}}\", \"{userInput}\");";

            // Insecure regex example (ReDoS)
            string evilInput = new string('a', 10000) + "!";
            string pattern = "(a+)+!";
            try
            {
                Regex.Match(evilInput, pattern);
                InsecureRegexExample = $"Regex.Match(evilInput, \"{pattern}\"); // Potential ReDoS";
            }
            catch { }
        }
    }
}
