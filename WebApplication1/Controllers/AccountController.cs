using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using WebApplication1.Models;
using WebApplication1.Util;
using System.Data.Entity;
using System.Data.SqlClient;
using System.Data;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;

namespace WebApplication1.Controllers
{
    
    public class AccountController : Controller
    {
        SqlConnection con = new SqlConnection(@"Data Source=DESKTOP-5H7S0ED;Initial Catalog=PassSecurity;Integrated Security=True");
        public MydemoEntities mde = new MydemoEntities();
        //xss の対策
        public class Xss
        {
            public static bool HasXssChars(string str)
            {
                if (Regex.IsMatch(str, "[&<>\"']"))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
        }

        //csrf の対策 偽造防止機能の構成 (Iアンチ偽造) Iアンチ偽造 は、偽造防止機能を構成するための API を提供します。 IAntiforgery は Configure 、クラスのメソッドで要求でき Startup ます。
        public void Configure(IApplicationBuilder app, IAntiforgery antiforgery)
        {
            app.Use(next => context =>
            {
                string path = context.Request.Path.Value;

                if (
                    string.Equals(path, "/", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(path, "/index.html", StringComparison.OrdinalIgnoreCase))
                {
                    // The request token can be sent as a JavaScript-readable cookie, 
                    // and Angular uses it by default.
                    var tokens = antiforgery.GetAndStoreTokens(context);
                    context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken,
                        new CookieOptions() { HttpOnly = false });
                }

                return next(context);
            });
        }

        public ActionResult Index()
        {
            //sql injection の対策：parameter コンストラクタ
            SqlCommand cmd = new SqlCommand("select * from Account where password = @password and username = @username", con);
            SqlParameter param = new SqlParameter();
            param.ParameterName = "@password";
            param.ParameterName = "@username";
            cmd.Parameters.Add(param);
            //sql injection の対策：parameter コンストラクタ
            return View("Index", new Account());
        }

        [HttpGet]
        public ActionResult Register()
        {
            
            return View("Register", new Account());
        }
        [HttpPost]
        public ActionResult Register(Account account)
        {
            account.password = Hashing.HashPassword(account.password);
            mde.Account.Add(account);
            mde.SaveChanges();
            return RedirectToAction("Index", "Account");  
        }
        [HttpPost]
        public ActionResult Login(Account account)
        {
            var currentAccount = mde.Account.SingleOrDefault(a => a.username.Equals(account.username));
            if(currentAccount != null)
            {
                if(Hashing.ValidatePassword(account.password, currentAccount.password))
                {
                    Session.Add("username", account.username);
                    return View("Wellcome");
                }
                
            }
            
                ViewBag.error = "Invalid";
                return View("Index");
            
        }
        public ActionResult Logout()
        {
            Session.Remove("");
            return RedirectToAction("Index", "Account");
        }
    }
}