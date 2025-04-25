using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace webapp01.Pages;

public class PrivacyModel : PageModel
{
    private readonly ILogger<PrivacyModel> _logger;

    string adminUserName = "demouser@example.com";

    // TODO: Don't use this in production
    public const string DEFAULT_PASSWORD = "Pass@word1";

    public PrivacyModel(ILogger<PrivacyModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
        string drive = Request.Query.ContainsKey("drive") ? Request.Query["drive"] : "C";
        var str = $"/C fsutil volume diskfree {drive}:";
        _logger.LogInformation($"Command str: {str}");
        _logger.LogInformation("Admin" + adminUserName);
        _logger.LogInformation($"User: {User.Identity?.Name}");
        _logger.LogInformation($"Admin: {User.IsInRole("Admin")}");
    }
}

