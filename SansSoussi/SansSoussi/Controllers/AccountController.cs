using System;
using System.Collections.Generic;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using System.Web.Security;
using SansSoussi.Models;
using System.Threading.Tasks;
using System.Net.Http;
using Newtonsoft.Json;
using System.Data.SqlClient;
using System.Web.Configuration;

namespace SansSoussi.Controllers
{
    public class AccountController : Controller
    {

        public IFormsAuthenticationService FormsService { get; set; }
        public IMembershipService MembershipService { get; set; }
        private static bool googleAuthentification = false;
        private static LogOnModel logOnModelGoogle;

        SqlConnection _dbConnection;

        public AccountController()
        {
            _dbConnection = new SqlConnection(WebConfigurationManager.ConnectionStrings["ApplicationServices"].ConnectionString);
        }

        protected override void Initialize(RequestContext requestContext)
        {
            if (FormsService == null) { FormsService = new FormsAuthenticationService(); }
            if (MembershipService == null) { MembershipService = new AccountMembershipService(); }

            base.Initialize(requestContext);
        }

        // **************************************
        // URL: /Account/LogOn
        // **************************************

        public ActionResult LogOn()
        {
            if (googleAuthentification == false)
            {
                return View(new LogOnModel() { googleAuthentification = false });
            }
            else
            {
                return View(new LogOnModel() { UserName = logOnModelGoogle.UserName, email = logOnModelGoogle.email, googleAuthentification = true });
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOn(LogOnModel model, string returnUrl)
        {
            if (googleAuthentification == false)
            {
                if (ModelState.IsValid)
                {
                    if (MembershipService.ValidateUser(model.UserName, model.Password))
                    {
                        FormsService.SignIn(model.UserName, model.RememberMe);
                        if (Url.IsLocalUrl(returnUrl))
                        {
                            return Redirect(returnUrl);
                        }
                        else
                        {
                            //Encode the username in base64
                            byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(model.UserName);
                            HttpCookie authCookie = new HttpCookie("username", System.Convert.ToBase64String(toEncodeAsBytes));
                            authCookie.HttpOnly = true;
                            authCookie.Secure = true;
                            HttpContext.Response.Cookies.Add(authCookie);
                            googleAuthentification = false;
                            return RedirectToAction("Index", "Home");
                        }
                    }
                    else
                    {
                        ModelState.AddModelError("", "The user name or password provided is incorrect.");
                    }
                }
            }
            else
            {
                List<string> searchResults = new List<string>();
                bool isInBDD = false;

                //Encode the username in base64
                SqlCommand cmd = new SqlCommand("Select UserName from aspnet_Users", _dbConnection);
                _dbConnection.Open();
                SqlDataReader rd = cmd.ExecuteReader();
                while (rd.Read())
                {
                    searchResults.Add(rd.GetString(0));
                }
                rd.Close();
                _dbConnection.Close();

                foreach (String username in searchResults)
                {
                    if (username == model.UserName)
                    {
                        isInBDD = true;
                    }
                }

                if (!isInBDD)
                {
                    MembershipCreateStatus createStatus = MembershipService.CreateUser(model.UserName, Guid.NewGuid().ToString(), model.email);
                }

                FormsService.SignIn(model.UserName, model.RememberMe);

                //Encode the username in base64
                byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(model.UserName);
                HttpCookie authCookie = new HttpCookie("username", System.Convert.ToBase64String(toEncodeAsBytes));
                authCookie.HttpOnly = true;
                authCookie.Secure = true;
                HttpContext.Response.Cookies.Add(authCookie);
                googleAuthentification = false;
                return RedirectToAction("Index", "Home");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        // **************************************
        // URL: /Account/LogOff
        // **************************************

        public ActionResult LogOff()
        {
            string[] myCookies = Request.Cookies.AllKeys;
            foreach (string cookie in myCookies)
            {
                Response.Cookies[cookie].Expires = DateTime.Now.AddDays(-1d);
            }

            Session.Abandon();
            FormsService.SignOut();
            googleAuthentification = false;
            return RedirectToAction("Index", "Home");
        }

        // **************************************
        // URL: /Account/Register
        // **************************************

        public ActionResult Register()
        {
            ViewBag.PasswordLength = MembershipService.MinPasswordLength;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                // Attempt to register the user
                MembershipCreateStatus createStatus = MembershipService.CreateUser(model.UserName, model.Password, model.Email);

                if (createStatus == MembershipCreateStatus.Success)
                {
                    
                    FormsService.SignIn(model.UserName, false /* createPersistentCookie */);
                    //Encode the username in base64
                    byte[] toEncodeAsBytes = System.Text.ASCIIEncoding.ASCII.GetBytes(model.UserName);
                    HttpCookie authCookie = new HttpCookie("username", System.Convert.ToBase64String(toEncodeAsBytes));
                    authCookie.HttpOnly = true;
                    authCookie.Secure = true;
                    HttpContext.Response.Cookies.Add(authCookie);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("", AccountValidation.ErrorCodeToString(createStatus));
                }
            }

            // If we got this far, something failed, redisplay form
            ViewBag.PasswordLength = MembershipService.MinPasswordLength;
            return View(model);
        }

        // **************************************
        // URL: /Account/ChangePassword
        // **************************************

        [Authorize]
        public ActionResult ChangePassword()
        {
            ViewBag.PasswordLength = MembershipService.MinPasswordLength;
            return View();
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ChangePassword(ChangePasswordModel model)
        {
            if (ModelState.IsValid)
            {
                if (MembershipService.ChangePassword(User.Identity.Name, model.OldPassword, model.NewPassword))
                {
                    return RedirectToAction("ChangePasswordSuccess");
                }
                else
                {
                    ModelState.AddModelError("", "The current password is incorrect or the new password is invalid.");
                }
            }

            // If we got this far, something failed, redisplay form
            ViewBag.PasswordLength = MembershipService.MinPasswordLength;
            return View(model);
        }

        // **************************************
        // URL: /Account/ChangePasswordSuccess
        // **************************************

        public ActionResult ChangePasswordSuccess()
        {
            return View();
        }

        // **************************************
        // Connection avec google
        // *************************************

        // CLIENT ID AND SECRETSHOULD NOT BE STORED IN CODE OR CONFIG, use Default Credentials or other safe method
        private const string CLIENT_ID = "515669744530-enf9gh78dkkqa6qr5i9u4rfled5nrcqs.apps.googleusercontent.com";
        private const string CLIENT_SECRET = "omilv7rXRoxRRGuhQLNvHSNn";


        public ActionResult RedirectToGoogle()
        {
            // Build the login oauth url
            var scopes = "email profile";                               // what we want to access
            var redirectUrl = "https://localhost:44348/Account/Callback";   // the url to which Google should send the user back to complete authentication
            var clientID = CLIENT_ID;                                   // SHOULD BE IN A SAFE PLACE, NOT HERE!

            googleAuthentification = true;

            // redirect user to the login url
            var oauthUrl = string.Format("https://accounts.google.com/o/oauth2/v2/auth?scope={0}&redirect_uri={1}&response_type=code&client_id={2}", scopes, redirectUrl, clientID);
            return Redirect(oauthUrl);
        }

        public async Task<ActionResult> Callback(string code)
        {
            // build the request to validate the incoming code
            var clientID = CLIENT_ID;                                   // from the Google API console, SHOULD BE IN A SAFE PLACE, NOT HERE!
            var clientSecret = CLIENT_SECRET;                           // from the Google API console, SHOULD BE IN A SAFE PLACE, NOT HERE!
            var redirectUri = "https://localhost:44348/Account/Callback";   // the original url we sent must match what we original set as the callback
            var grantType = "authorization_code";                       // this tells OAUTH we're using a code to validate


            // wrap parameters in a Form object
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("code", code),   // the code we got from the callback
                new KeyValuePair<string, string>("client_id", clientID),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("grant_type", grantType),
            });

            // the url to send the POST request (from the google docs)
            var postUrl = "https://accounts.google.com/o/oauth2/token";

            // submit the request
            var client = new HttpClient();
            var result = await client.PostAsync(postUrl, content);

            // get the result as a string
            var resultContent = await result.Content.ReadAsStringAsync();

            // parse the result into an object
            var resultObject = new { access_token = "" };
            var json = JsonConvert.DeserializeAnonymousType(resultContent, resultObject);

            // use the token to get the user's profile
            var url = "https://www.googleapis.com/oauth2/v1/userinfo";
            client.DefaultRequestHeaders.Add("Authorization", "Bearer " + json.access_token);
            var response = await client.GetStringAsync(url);

            // parse the new result to get the profile
            var profileResultObject = new { id = "", email = "", verified_email = "", given_name = "" , family_name =""};
            var profileJson = JsonConvert.DeserializeAnonymousType(response, profileResultObject);

            logOnModelGoogle = new LogOnModel();
            logOnModelGoogle.UserName = profileJson.given_name + profileJson.family_name;
            logOnModelGoogle.email = profileJson.email;

            // redirect to a result page
            return RedirectToAction("LogOn"); 
        }
    }
}
