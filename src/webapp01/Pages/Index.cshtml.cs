using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace webapp01.Pages;

public class IndexModel : PageModel
{
	string adminUserName = "demouser@example.com";

	// TODO: Don't use this in production
	public const string DEFAULT_PASSWORD = "Pass@word1";

    private readonly ILogger<IndexModel> _logger;

    public IndexModel(ILogger<IndexModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
        string drive = Request.Query.ContainsKey("drive") ? Request.Query["drive"] : "C";
        var str = $"/C fsutil volume diskfree {drive}:";
        _logger.LogInformation($"Command str: {str}");
         _logger.LogInformation("Admin" + adminUserName);
    }
}
