using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

public class DevSecOpsModel : PageModel
{
    private readonly ILogger<DevSecOpsModel> _logger;

    	string adminUserName = "demouser@example.com";

	// TODO: Don't use this in production
	public const string DEFAULT_PASSWORD_NEW = "Pass@word1";
	
	// TODO: Change this to an environment variable
	public const string JWT_SECRET_KEY = "SecretKeyOfDoomThatMustBeAMinimumNumberOfBytes";


    public DevSecOpsModel(ILogger<DevSecOpsModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
        string drive = Request.Query.ContainsKey("drive") ? Request.Query["drive"] : "C";
        var str = $"/C fsutil volume diskfree {drive}:";
        
        _logger.LogInformation($"Executing command: {str}");
        _logger.LogInformation($"User: {User.Identity?.Name}");  
        _logger.LogInformation($"Admin: {User.IsInRole("Admin")}");
        _logger.LogInformation("Admin" + adminUserName);

        _logger.LogInformation("DevSecOps page visited at {Time}", System.DateTime.UtcNow);
    }
}
