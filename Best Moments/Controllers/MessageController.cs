using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Best_Moments.Models;
using WebMatrix.WebData;
using Best_Moments.Filters;

namespace Best_Moments.Controllers
{
    [HandleError]
    [InitializeSimpleMembership]
    public class MessageController : Controller
    {
        private UsersContext db = new UsersContext();

        public ActionResult SendMessage(string UserName)
        {
            //try to fetch user profile
            UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.ToLower() == UserName.ToLower());
            if (user == null)
            {
                return RedirectToAction("NotFound", "Error");
            }
            return View(user);
        }
        [HttpPost]
        public ActionResult SendMessage(string UserName , string SenderMessage)
        {
            UserProfile user = db.UserProfiles.FirstOrDefault(u => u.UserName.ToLower() == UserName.ToLower());
            var Id = WebSecurity.GetUserId(UserName);
            Message message= new Message();
            if (ModelState.IsValid)
            {
                message.MessageBody = SenderMessage;
                message.MessageDate = DateTime.Now.ToString();
                message.UserId = Id;
                db.Messages.Add(message);
                db.SaveChanges();
                return RedirectToAction("ThankYou","Message");
            }
            return View(user);
        }

        public ActionResult ThankYou()
        {
            return View();
        }

    }
}