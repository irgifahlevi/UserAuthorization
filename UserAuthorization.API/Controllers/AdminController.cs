using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace UserAuthorization.API.Controllers
{
    [Authorize(Roles = "Admin")]
    [Route("api/[controller]")]
    [ApiController]

    public class AdminController : ControllerBase
    {

        private List<string> employee;

        [HttpGet]
        [Route("GetEmployee")]
        public IEnumerable<string> GetEmployee()
        {
            return employee = new List<string>()
            {
                "Jane", "Salman", "Max", "Andrew", "Luccyan", "Matt"
            };
        }
    }


}
