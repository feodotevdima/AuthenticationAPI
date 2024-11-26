﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Core.Models
{
    public class UserModel
    {
        public Guid Id { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }

        public UserModel(string email, string password)
        {
            Email = email;
            Password = password;
        }
    }
}
