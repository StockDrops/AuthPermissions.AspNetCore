﻿// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace ExamplesCommonCode.DemoSetupCode
{
    public static class AspNetUserExtension
    {
        public static async Task<List<IdentityUser>> AddDemoUsersAsync(this IServiceProvider serviceProvider,
            IEnumerable<string> usersEmails)
        {
            var userManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();
            var result = new List<IdentityUser>();
            foreach (var userEmail in usersEmails)
            {
                var user = await userManager.CheckAddNewUserAsync(userEmail, userEmail);
                result.Add(user);
            }

            return result;
        }

        /// <summary>
        /// This will add a user with the given email if they don't all ready exist
        /// </summary>
        /// <param name="userManager"></param>
        /// <param name="email"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private static async Task<IdentityUser> CheckAddNewUserAsync(this UserManager<IdentityUser> userManager, string email, string password)
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user != null)
                return user;
            user = new IdentityUser { UserName = email, Email = email };
            var result = await userManager.CreateAsync(user, password);
            if (!result.Succeeded)
            {
                var errorDescriptions = string.Join("\n", result.Errors.Select(x => x.Description));
                throw new InvalidOperationException(
                    $"Tried to add user {email}, but failed. Errors:\n {errorDescriptions}");
            }

            return user;
        }
    }
}