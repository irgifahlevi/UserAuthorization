﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UserAuthorization.Facade.Models;

namespace UserAuthorization.Facade.Services
{
    public interface IEmailRepository
    {
        public void SendEmail(Message message);
        public bool IsValidEmail(string email);
    }
}
