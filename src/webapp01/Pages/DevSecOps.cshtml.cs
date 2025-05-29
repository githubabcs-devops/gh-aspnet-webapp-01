using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.RegularExpressions;
using System.Data.SqlClient;
using Microsoft.Data.SqlClient;
using Newtonsoft.Json;

namespace webapp01.Pages
{
    public class DevSecOpsModel : PageModel
    {
        private readonly ILogger<DevSecOpsModel> _logger;
        
        // Insecure: Hard-coded connection string for demo purposes
        private const string CONNECTION_STRING = "Server=localhost;Database=DemoDb;User Id=sa;Password=P@ssw0rd123;";
        
        // Insecure: Vulnerable regex pattern for demo purposes  
        private static readonly Regex EmailRegex = new Regex(@"^(.+)@(.+)$", RegexOptions.Compiled);

        public DevSecOpsModel(ILogger<DevSecOpsModel> logger)
        {
            _logger = logger;
        }

        public List<string> LatestNews { get; set; } = new List<string>();
        public string UserInput { get; set; } = string.Empty;

        public void OnGet()
        {
            _logger.LogInformation("DevSecOps page accessed at {Time}", DateTime.UtcNow);
            
            LoadLatestGHASNews();
            
            // Insecure: Log user data without sanitization for demo purposes
            string userAgent = Request.Headers["User-Agent"].ToString();
            _logger.LogInformation("User accessed DevSecOps page with User-Agent: " + userAgent);
        }

        public void OnPost(string userInput)
        {
            UserInput = userInput ?? string.Empty;
            
            // Insecure: Log forging vulnerability for demo purposes
            _logger.LogInformation("User input received: " + userInput + " from user: " + User.Identity?.Name);
            
            // Insecure: SQL injection vulnerability for demo purposes
            if (!string.IsNullOrEmpty(userInput))
            {
                try
                {
                    using var connection = new SqlConnection(CONNECTION_STRING);
                    var query = $"SELECT * FROM Users WHERE Name = '{userInput}'"; // Vulnerable to SQL injection
                    _logger.LogWarning("Executing query: " + query);
                }
                catch (Exception ex)
                {
                    _logger.LogError("Database error: " + ex.Message);
                }
            }
              // Insecure: Regex vulnerability for demo purposes
            if (!string.IsNullOrEmpty(userInput) && EmailRegex.IsMatch(userInput))
            {
                _logger.LogInformation("Valid email format detected");
            }
            
            LoadLatestGHASNews();
        }

        private void LoadLatestGHASNews()
        {
            LatestNews = new List<string>
            {
                "GitHub Advanced Security now supports AI-powered code scanning with enhanced vulnerability detection",
                "New Dependabot features include automated security updates for container dependencies", 
                "Secret scanning now detects over 200+ token types including cloud provider keys",
                "Code scanning with CodeQL now supports Python 3.12 and enhanced C# analysis",
                "Dependency review action helps prevent vulnerable dependencies in pull requests",
                "GHAS now integrates with third-party security tools through the Security tab API",
                "Enhanced supply chain security with SLSA compliance and artifact attestation",
                "New security advisories database provides comprehensive vulnerability information"
            };

            _logger.LogInformation("Loaded {Count} GHAS news items", LatestNews.Count);
        }
    }
}
