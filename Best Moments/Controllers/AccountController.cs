using System;
using System.Collections.Generic;
using System.Linq;
using System.Transactions;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using DotNetOpenAuth.AspNet;
using Microsoft.Web.WebPages.OAuth;
using WebMatrix.WebData;
using Best_Moments.Filters;
using Best_Moments.Models;
using CaptchaMvc.HtmlHelpers;
using System.Web.Helpers;
using System.Net;
using System.Net.Mail;
using System.IO;
using System.Data;
namespace Best_Moments.Controllers
{
    [HandleError]
    [Authorize]
    [InitializeSimpleMembership]
    public class AccountController : Controller
    {
        //
        // GET: /Account/Login

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginModel model, string returnUrl)
        {
            if (ModelState.IsValid && WebSecurity.Login(model.UserName, model.Password, persistCookie: model.RememberMe))
            {
                return RedirectToAction("MyProfile", "Account");
            }

            // If we got this far, something failed, redisplay form
            ModelState.AddModelError("", "The user name or password provided is incorrect.");
            return View(model);
        }

        //
        // POST: /Account/LogOff

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            WebSecurity.Logout();

            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/Register

        [AllowAnonymous]
        public ActionResult Register()
        {
            ViewBag.Gender = new SelectList(new[] { "Male", "Female" });
            return View();
        }

        //
        // POST: /Account/Register

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterModel model)
        {
            ViewBag.Gender = new SelectList(new[] { "Male", "Female"});

            if (ModelState.IsValid)
            {
                if (this.IsCaptchaValid("Captcha is not valid"))
                {
                    try
                    {
                        MailMessage MM = new MailMessage("best.moments.site@gmail.com", model.Email);
                        MM.Subject = "Registration Completed Successfully";
                        MM.Body = "Welcome To Memento Site";
                        MM.IsBodyHtml = false;

                        SmtpClient Smtp = new SmtpClient();
                        Smtp.Host = "smtp.gmail.com";
                        Smtp.Port = 587;
                        Smtp.EnableSsl = true;

                        NetworkCredential NC = new NetworkCredential("best.moments.site@gmail.com", "emo621995");
                        Smtp.UseDefaultCredentials = true;
                        Smtp.Credentials = NC;
                        Smtp.Send(MM);

                    }
                    catch (Exception)
                    {
                        ViewBag.Status = "Problem while sending email, Please check your Email";
                    }

                    try
                    {
                        // Attempt to register the user
                        WebSecurity.CreateUserAndAccount(model.UserName, model.Password, new { Email = model.Email, FirstName = model.FirstName, LastName = model.LastName, Gender = model.Gender, Image = model.Image = "Default-Image-Profile.jpg"});
                        WebSecurity.Login(model.UserName, model.Password);
                        return RedirectToAction("MyProfile", "Account");
                    }
                    catch (MembershipCreateUserException e)
                    {
                        ModelState.AddModelError("", ErrorCodeToString(e.StatusCode));
                    }
                }
                else
                {
                    ViewBag.ErrorCaptcha = "Error: Captcha is not valid.";
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }
        public UsersContext db = new UsersContext();
        //---------------------------------
        //Start Forgot Password Implementation
        private string GenerateRandomPassword(int length)
        {
            string allowedChars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789";
            char[] chars = new char[length];
            Random rd = new Random();
            for (int i = 0; i < length; i++)
            {
                chars[i] = allowedChars[rd.Next(0, allowedChars.Length)];
            }
            return new string(chars);
        }

        private void SendEMail(string email, string subject, string body)
        {
            SmtpClient client = new SmtpClient();
            client.DeliveryMethod = SmtpDeliveryMethod.Network;
            client.EnableSsl = true;
            client.Host = "smtp.gmail.com";
            client.Port = 587;

            System.Net.NetworkCredential credentials = new System.Net.NetworkCredential("best.moments.site@gmail.com", "emo621995");
            client.UseDefaultCredentials = false;
            client.Credentials = credentials;

            MailMessage msg = new MailMessage();
            msg.From = new MailAddress("best.moments.site@gmail.com");
            msg.To.Add(new MailAddress(email));

            msg.Subject = subject;
            msg.IsBodyHtml = true;
            msg.Body = body;

            client.Send(msg);
        }

        [HttpGet]
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ForgotPassword(string UserName)
        {
            //check user existance
            var user = Membership.GetUser(UserName);
            if (user == null)
            {
                TempData["Message"] = "User Not exist.";
            }
            else
            {
                //generate password token
                var token = WebSecurity.GeneratePasswordResetToken(UserName);
                //create url with above token
                var ResetPassword = "<a href='" + Url.Action("ResetPassword", "Account", new { un = UserName, rt = token }, "http") + "'>Reset Password</a>";
                //get user email
                var email = (from i in db.UserProfiles
                               where i.UserName == UserName
                               select i.Email).FirstOrDefault();
                //send mail
                string subject = "Password Reset Token";
                string body = "<b>Click to the Link Below to Reset Your Password </b><br/>" + ResetPassword;
                try
                {
                    SendEMail(email, subject, body);
                    TempData["Message"] = "Check Your Mail.";
                }
                catch (Exception ex)
                {
                    TempData["Message"] = "Error occured while sending email." + ex.Message;
                }
            }

            return View();
        }

        [AllowAnonymous]
        public ActionResult ResetPassword(string un, string rt)
        {
            //TODO: Check the un and rt matching and then perform following
            //get userid of received username
            var userid = (from i in db.UserProfiles
                          where i.UserName == un
                          select i.UserId).FirstOrDefault();
            //check userid and token matches
            bool any = (from j in db.webpages_Memberships
                        where (j.UserId == userid)
                        && (j.PasswordVerificationToken == rt)
                        select j).Any();

            if (any == true)
            {
                //generate random password
                string newpassword = GenerateRandomPassword(6);
                //reset password
                bool response = WebSecurity.ResetPassword(rt, newpassword);
                if (response == true)
                {
                    //get user emailid to send password
                    var email = (from i in db.UserProfiles
                                   where i.UserName == un
                                   select i.Email).FirstOrDefault();
                    //send email
                    string subject = "New Password";
                    string body = "<b>Please find the New Password</b><br/>" + newpassword;
                    try
                    {
                        SendEMail(email, subject, body);
                        TempData["Message"] = "A Mail Sent to You with a New Password.";
                    }
                    catch (Exception ex)
                    {
                        TempData["Message"] = "Error occured while sending email." + ex.Message;
                    }

                    //display message
                    TempData["Message"] = "A Mail Sent to You with a New Password.";
                }
                else
                {
                    TempData["Message"] = "Hey, avoid random request on this page.";
                }
            }
            else
            {
                TempData["Message"] = "Username and Token not Matching.";
            }

            return View();
        }
        //End Forgot Password Implementation

        //---------------------------------
        //Start Is User Exists
        public JsonResult IsUserExists(string UserName)
        {
            UsersContext db = new UsersContext();
            //check if any of the UserName matches the UserName specified in the Parameter using the ANY extension method.  
            return Json(!db.UserProfiles.Any(x => x.UserName.ToLower() == UserName.ToLower()), JsonRequestBehavior.AllowGet);
        }
        //End Is User Exists
        //---------------------------------

       //----------------------------------
       //Start Edit User Profile Implementation
        public ActionResult EditProfile()
        {
            ViewBag.Gender = new SelectList(new[] { "Male", "Female" });
  
            string UserName = User.Identity.Name;

            // Fetch the UserProfile
            UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.Equals(UserName));
            // Construct the ViewModel
            UserProfile model = new UserProfile();
            model = user;
            return View(model);
        } 

        [HttpPost]
        public ActionResult EditProfile(UserProfile userprofile)
        {
            ViewBag.Gender = new SelectList(new[] { "Male", "Female" });
  
            if (ModelState.IsValid)
            {

                string username = User.Identity.Name;
                // Get the userprofile

                UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.ToLower() == username.ToLower());
                UserProfile UserExist = db.UserProfiles.FirstOrDefault(u => u.UserName.ToLower() == userprofile.UserName.ToLower());
                // Check if user already exists
                if (UserExist == null || userprofile.UserName.ToLower() == username.ToLower())
                {
                    //Doesn't Change User Nmae
                    if (userprofile.UserName.ToLower() == username.ToLower())
                    {
                        user.UserName = userprofile.UserName;
                        user.Email = userprofile.Email;
                        user.FirstName = userprofile.FirstName;
                        user.LastName = userprofile.LastName;
                        user.Gender = userprofile.Gender;
                        
                        db.Entry(user).State = System.Data.EntityState.Modified;

                        db.SaveChanges();
                        return RedirectToAction("MyProfile", "Account"); // or whatever
                    }
                    //Changed User Nmae
                    else
                    {
                        user.UserName = userprofile.UserName;
                        user.Email = userprofile.Email;
                        user.FirstName = userprofile.FirstName;
                        user.LastName = userprofile.LastName;
                        user.Gender = userprofile.Gender;
                        
                        db.Entry(user).State = System.Data.EntityState.Modified;

                        db.SaveChanges();
                        FormsAuthentication.SignOut();
                        return RedirectToAction("ReLogin", "Account"); // or whatever

                    }
                }
                else
                {
                    ModelState.AddModelError("UserName", "User name already exists. Please enter a different user name.");
                }

            }

            return View(userprofile);
        }
        //End Edit User Profile Implementation
        //------------------------------------

        [AllowAnonymous]
        public ActionResult ReLogin()
        {
            return View();
        } 

        //----------------------------------
        //Start Delete User Implementation
        public ActionResult DeleteAccount()
        {
            return View();
        }
        [HttpPost]
        public ActionResult DeleteAccount(UserProfile userprofile)
        {
            var Id = WebSecurity.GetUserId(User.Identity.Name);
            var messages = db.Messages.Where(w => w.UserId == Id);
            foreach (Message message in messages)
            {
                db.Messages.Remove(message);
            }
            db.SaveChanges();

            var membership = (SimpleMembershipProvider)Membership.Provider;
            membership.DeleteAccount(User.Identity.Name);
            membership.DeleteUser(User.Identity.Name, true);
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Home");//or whatever
        }
        //End Delete User Implementation
        //------------------------------------

        //------------------------------------
        //Start User Profile
        public ActionResult MyProfile()
        {
            var Id = WebSecurity.GetUserId(User.Identity.Name);
            List<Message> messages = (from m in db.Messages
                                      where m.UserId == Id
                                      select m).ToList();

            ViewBag.MessagesCount = messages.Count();

            string UserName = User.Identity.Name;
            // Get the userprofile

            UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.ToLower() == UserName.ToLower());
            if (user == null)
            {
                return HttpNotFound();
            }
            return View(user);
        }
        //End User Profile
        //------------------------------------
        
        //------------------------------------
        //Start Upload New Photo
        [HttpPost]
        public ActionResult UploadPhoto()
        {
            string username = User.Identity.Name;

            // Fetch the userprofile
            UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.Equals(username));

            // Checking no. of files injected in Request object  
            if (Request.Files.Count > 0)
            {
                //remove old Photo from server
                string fullPath = Request.MapPath("~/Uploades/" + user.Image);

                if (System.IO.File.Exists(fullPath))
                {
                    System.IO.File.Delete(fullPath);
                }
                //Get file from Request object  
                HttpFileCollectionBase files = Request.Files;
                HttpPostedFileBase ProfilePhoto = files[0];

                var PhotoName = Guid.NewGuid().ToString() + Path.GetExtension(ProfilePhoto.FileName);
                var uploadUrl = Server.MapPath("~/Uploades");
                ProfilePhoto.SaveAs(Path.Combine(uploadUrl, PhotoName));

                user.Image = PhotoName;
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();

                // Returns message that successfully uploaded  
                return RedirectToAction("MyProfile", "Account");

            }
            else
            {
                return Json("No files selected !!!");
            }

        }

        //End Upload New Photo
        //------------------------------------


        //------------------------------------
        //Start Remove Photo
        [HttpPost]
        public ActionResult RemovePhoto()
        {
            string username = User.Identity.Name;

            // Fetch the userprofile
            UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.Equals(username));
            if (user.Image == "Default-Image-Profile.jpg")
            { /*Nothing to do*/ }
            else
            {
                // Remove old photo  
                string fullPath = Request.MapPath("~/Uploades/" + user.Image);

                if (System.IO.File.Exists(fullPath))
                {
                    System.IO.File.Delete(fullPath);
                }

                user.Image = "Default-Image-Profile.jpg";
                db.Entry(user).State = EntityState.Modified;
                db.SaveChanges();

                return RedirectToAction("MyProfile", "Account");
            }
            return View();
        }
        //End Remove Photo
        //------------------------------------
        //Account Setting
        public ActionResult Setting()
        {
            return View();
        }
        //------------------------------------
        //Start Delete Message
        public JsonResult DeleteMessage(int id)
        {
           
            Message message = db.Messages.Find(id);
            db.Messages.Remove(message);
            db.SaveChanges();
            bool result = true;
            return Json(result,JsonRequestBehavior.AllowGet);
        }
        //End Delete Message
        //------------------------------------




        //
        // POST: /Account/Disassociate

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Disassociate(string provider, string providerUserId)
        {
            string ownerAccount = OAuthWebSecurity.GetUserName(provider, providerUserId);
            ManageMessageId? message = null;

            // Only disassociate the account if the currently logged in user is the owner
            if (ownerAccount == User.Identity.Name)
            {
                // Use a transaction to prevent the user from deleting their last login credential
                using (var scope = new TransactionScope(TransactionScopeOption.Required, new TransactionOptions { IsolationLevel = System.Transactions.IsolationLevel.Serializable }))
                {
                    bool hasLocalAccount = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
                    if (hasLocalAccount || OAuthWebSecurity.GetAccountsFromUserName(User.Identity.Name).Count > 1)
                    {
                        OAuthWebSecurity.DeleteAccount(provider, providerUserId);
                        scope.Complete();
                        message = ManageMessageId.RemoveLoginSuccess;
                    }
                }
            }

            return RedirectToAction("Manage", new { Message = message });
        }

        //
        // GET: /Account/Manage

        public ActionResult Manage(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
                : "";
            ViewBag.HasLocalPassword = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
            ViewBag.ReturnUrl = Url.Action("Manage");
            return View();
        }

        //
        // POST: /Account/Manage

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Manage(LocalPasswordModel model)
        {
            bool hasLocalAccount = OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
            ViewBag.HasLocalPassword = hasLocalAccount;
            ViewBag.ReturnUrl = Url.Action("Manage");
            if (hasLocalAccount)
            {
                if (ModelState.IsValid)
                {
                    // ChangePassword will throw an exception rather than return false in certain failure scenarios.
                    bool changePasswordSucceeded;
                    try
                    {
                        changePasswordSucceeded = WebSecurity.ChangePassword(User.Identity.Name, model.OldPassword, model.NewPassword);
                    }
                    catch (Exception)
                    {
                        changePasswordSucceeded = false;
                    }

                    if (changePasswordSucceeded)
                    {
                        return RedirectToAction("Manage", new { Message = ManageMessageId.ChangePasswordSuccess });
                    }
                    else
                    {
                        ModelState.AddModelError("", "The current password is incorrect or the new password is invalid.");
                    }
                }
            }
            else
            {
                // User does not have a local password so remove any validation errors caused by a missing
                // OldPassword field
                ModelState state = ModelState["OldPassword"];
                if (state != null)
                {
                    state.Errors.Clear();
                }

                if (ModelState.IsValid)
                {
                    try
                    {
                        WebSecurity.CreateAccount(User.Identity.Name, model.NewPassword);
                        return RedirectToAction("Manage", new { Message = ManageMessageId.SetPasswordSuccess });
                    }
                    catch (Exception e)
                    {
                        ModelState.AddModelError("", e);
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // POST: /Account/ExternalLogin

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            return new ExternalLoginResult(provider, Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/ExternalLoginCallback

        [AllowAnonymous]
        public ActionResult ExternalLoginCallback(string returnUrl)
        {
            AuthenticationResult result = OAuthWebSecurity.VerifyAuthentication(Url.Action("ExternalLoginCallback", new { ReturnUrl = returnUrl }));
            if (!result.IsSuccessful)
            {
                return RedirectToAction("ExternalLoginFailure");
            }

            if (OAuthWebSecurity.Login(result.Provider, result.ProviderUserId, createPersistentCookie: false))
            {
                return RedirectToLocal(returnUrl);
            }

            if (User.Identity.IsAuthenticated)
            {
                // If the current user is logged in add the new account
                OAuthWebSecurity.CreateOrUpdateAccount(result.Provider, result.ProviderUserId, User.Identity.Name);
                return RedirectToLocal(returnUrl);
            }
            else
            {
                // User is new, ask for their desired membership name
                string loginData = OAuthWebSecurity.SerializeProviderUserId(result.Provider, result.ProviderUserId);
                ViewBag.ProviderDisplayName = OAuthWebSecurity.GetOAuthClientData(result.Provider).DisplayName;
                ViewBag.ReturnUrl = returnUrl;
                return View("ExternalLoginConfirmation", new RegisterExternalLoginModel { UserName = result.UserName, ExternalLoginData = loginData });
            }
        }

        //
        // POST: /Account/ExternalLoginConfirmation

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLoginConfirmation(RegisterExternalLoginModel model, string returnUrl)
        {
            string provider = null;
            string providerUserId = null;

            if (User.Identity.IsAuthenticated || !OAuthWebSecurity.TryDeserializeProviderUserId(model.ExternalLoginData, out provider, out providerUserId))
            {
                return RedirectToAction("Manage");
            }

            if (ModelState.IsValid)
            {
                // Insert a new user into the database
                using (UsersContext db = new UsersContext())
                {
                    UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.ToLower() == model.UserName.ToLower());
                    // Check if user already exists
                    if (user == null)
                    {
                        // Insert name into the profile table
                        db.UserProfiles.Add(new UserProfile { UserName = model.UserName });
                        db.SaveChanges();

                        OAuthWebSecurity.CreateOrUpdateAccount(provider, providerUserId, model.UserName);
                        OAuthWebSecurity.Login(provider, providerUserId, createPersistentCookie: false);

                        return RedirectToLocal(returnUrl);
                    }
                    else
                    {
                        ModelState.AddModelError("UserName", "User name already exists. Please enter a different user name.");
                    }
                }
            }

            ViewBag.ProviderDisplayName = OAuthWebSecurity.GetOAuthClientData(provider).DisplayName;
            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // GET: /Account/ExternalLoginFailure

        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        [AllowAnonymous]
        [ChildActionOnly]
        public ActionResult ExternalLoginsList(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return PartialView("_ExternalLoginsListPartial", OAuthWebSecurity.RegisteredClientData);
        }

        [ChildActionOnly]
        public ActionResult RemoveExternalLogins()
        {
            ICollection<OAuthAccount> accounts = OAuthWebSecurity.GetAccountsFromUserName(User.Identity.Name);
            List<ExternalLogin> externalLogins = new List<ExternalLogin>();
            foreach (OAuthAccount account in accounts)
            {
                AuthenticationClientData clientData = OAuthWebSecurity.GetOAuthClientData(account.Provider);

                externalLogins.Add(new ExternalLogin
                {
                    Provider = account.Provider,
                    ProviderDisplayName = clientData.DisplayName,
                    ProviderUserId = account.ProviderUserId,
                });
            }

            ViewBag.ShowRemoveButton = externalLogins.Count > 1 || OAuthWebSecurity.HasLocalAccount(WebSecurity.GetUserId(User.Identity.Name));
            return PartialView("_RemoveExternalLoginsPartial", externalLogins);
        }

        #region Helpers
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
        }

        internal class ExternalLoginResult : ActionResult
        {
            public ExternalLoginResult(string provider, string returnUrl)
            {
                Provider = provider;
                ReturnUrl = returnUrl;
            }

            public string Provider { get; private set; }
            public string ReturnUrl { get; private set; }

            public override void ExecuteResult(ControllerContext context)
            {
                OAuthWebSecurity.RequestAuthentication(Provider, ReturnUrl);
            }
        }

        private static string ErrorCodeToString(MembershipCreateStatus createStatus)
        {
            // See http://go.microsoft.com/fwlink/?LinkID=177550 for
            // a full list of status codes.
            switch (createStatus)
            {
                case MembershipCreateStatus.DuplicateUserName:
                    return "User name already exists. Please enter a different user name.";

                case MembershipCreateStatus.DuplicateEmail:
                    return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

                case MembershipCreateStatus.InvalidPassword:
                    return "The password provided is invalid. Please enter a valid password value.";

                case MembershipCreateStatus.InvalidEmail:
                    return "The e-mail address provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidAnswer:
                    return "The password retrieval answer provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidQuestion:
                    return "The password retrieval question provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidUserName:
                    return "The user name provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.ProviderError:
                    return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                case MembershipCreateStatus.UserRejected:
                    return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                default:
                    return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
            }
        }
        #endregion
    }
}
