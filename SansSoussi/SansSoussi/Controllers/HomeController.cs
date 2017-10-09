using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Data.SqlClient;
using System.Web.Configuration;
using System.Web.Security;
using System.Web.Helpers;
using System.Net.Http;

namespace SansSoussi.Controllers
{
    public class HomeController : Controller
    {
        SqlConnection _dbConnection;
        public HomeController()
        {
             _dbConnection = new SqlConnection(WebConfigurationManager.ConnectionStrings["ApplicationServices"].ConnectionString);
        }

        public ActionResult Index()
        {
            ViewBag.Message = "Parce que marcher devrait se faire SansSoussi";

            return View();
        }

        public ActionResult Comments()
        {
            List<string> comments = new List<string>();

            //Get current user from default membership provider
            MembershipUser user = Membership.Provider.GetUser(HttpContext.User.Identity.Name, true);
            if (user != null)
            {
                SqlCommand cmd = new SqlCommand("Select Comment from Comments where UserId ='" + user.ProviderUserKey + "'", _dbConnection);
                _dbConnection.Open();
                SqlDataReader rd = cmd.ExecuteReader();

                while (rd.Read())
                {
                    string comment = rd.GetString(0); //récuperer la valeur de la base de données 
                    string encoded = Server.HtmlEncode(comment); //encoder cette valeur en HTML
                    comments.Add(encoded); //Ajouter la valeur à la liste des commentaire 
                }

                rd.Close();
                _dbConnection.Close();
            }
            return View(comments);
        }

        [HttpPost]
        [ValidateInput(false)]
        public ActionResult Comments(string comment)
        {
            string status = "success";
            try
                {
                    //Get current user from default membership provider
                    MembershipUser user = Membership.Provider.GetUser(HttpContext.User.Identity.Name, true);
                    if (user != null)
                    {
                        // Using SqlCommand and Parameters to prevent Injection SQL in Search data 
                        SqlCommand cmd = new SqlCommand(
                            "insert into Comments (UserId, CommentId, Comment) Values (@user, @Guid , @Comment)",
                        _dbConnection);

                        cmd.Parameters.AddWithValue("@user", user.ProviderUserKey);
                        cmd.Parameters.AddWithValue("@Guid", Guid.NewGuid());
                        cmd.Parameters.AddWithValue("@Comment", comment);

                        _dbConnection.Open();

                        cmd.ExecuteNonQuery();
                    }
                    else
                    {
                        throw new Exception("Vous devez vous connecter");
                    }
                }

                catch (Exception ex)
                {
                    status = ex.Message;
                }
                finally
                {
                    _dbConnection.Close();
                }

                return Json(status);
        }

        public ActionResult Search(string searchData)
        {
            List<string> searchResults = new List<string>();

            //Get current user from default membership provider
            MembershipUser user = Membership.Provider.GetUser(HttpContext.User.Identity.Name, true);
            if (user != null)
            {
                if (!string.IsNullOrEmpty(searchData))
                {
                    // Using SqlCommand and Parameters to prevent Injection SQL in Search data 
                    SqlCommand cmd1 = new SqlCommand("Select Comment from Comments where UserId = @user and Comment like '%' +@Search + '%'", _dbConnection);
                    cmd1.Parameters.AddWithValue("@user", user.ProviderUserKey);
                    cmd1.Parameters.AddWithValue("@Search", searchData);

                    _dbConnection.Open();
                    SqlDataReader reader = cmd1.ExecuteReader();


                    while (reader.Read())
                    {
                        string search = reader.GetString(0); //recupérer la valeur de la base de donnée 
                        string encoded = Server.HtmlEncode(search); //encoder en HTML cette valeur
                        searchResults.Add(encoded); // Ajouter la valeur à la liste des résultats 
                    }

                    reader.Close();
                    _dbConnection.Close();
                }
            }
            return View(searchResults);
        }

        [HttpGet]
        public ActionResult Emails()
        {
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "admin")]
        [ValidateAntiForgeryToken]
        public ActionResult Emails(object form)
        {
            List<string> searchResults = new List<string>();

            HttpCookie cookie = HttpContext.Request.Cookies["username"];
            
            List<string> cookieString = new List<string>();

            //Decode the cookie from base64 encoding
            byte[] encodedDataAsBytes = System.Convert.FromBase64String(cookie.Value);
            string strCookieValue = System.Text.ASCIIEncoding.ASCII.GetString(encodedDataAsBytes);

            //get user role base on cookie value
            string[] roles = Roles.GetRolesForUser(strCookieValue);

            bool isAdmin = roles.Contains("admin");

            if (isAdmin)
            {
                SqlCommand cmd = new SqlCommand("Select Email from aspnet_Membership", _dbConnection);
                _dbConnection.Open();
                SqlDataReader rd = cmd.ExecuteReader();
                while (rd.Read())
                {
                    searchResults.Add(rd.GetString(0));
                }
                rd.Close();
                _dbConnection.Close();
            }


            return Json(searchResults);
        }

        public ActionResult About()
        {
            return View();
        }
    }
}
