using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace webapp01.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(ILogger<IndexModel> logger)
    {
        _logger = logger;

       	string drive = Request.Query.ContainsKey("drive") ? Request.Query["drive"] : "C";
	    
        var str = $"/C fsutil volume diskfree {drive}:";

        _logger.LogInformation($"Command str issue: {str}");
    }

    public void OnGet()
    {

    }
}
