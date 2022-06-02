using AuthPermissions.AdminCode;
using AuthPermissions.BaseCode.CommonCode;
using AuthPermissions.BaseCode.PermissionsCode;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AuthPermissions.AspNetCore.OpenIdCode
{
    /// <summary>
    /// This middleware is intended for an easy way of adding the claims to the User when you are using an API protected by Azure AD or Azure AD B2C. In those case, you do not login using the API app but instead use Azure for it. Hence you will not have the claims needed.
    /// This code runs before the authorization middlewares and will add the claims if there's no permission claims in the token.
    /// Remember to register this in your startup code between app.UseAuthentication() and app.UseAuthorization().
    /// Another way to do this is to use an API connector, but this requires a lot more work both on the Azure end of things and in the API since you have to code an API controller for this case.
    /// </summary>
    public class AzureAdClaimApiMiddleware
    {
        private readonly RequestDelegate _next;
        ///<inheritdoc/>
        public AzureAdClaimApiMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        /// <summary>
        /// If the user is logged in, this middleware will add the permission claims to the user.
        /// </summary>
        /// <param name="httpContext"></param>
        /// <param name="settings">This is injected by ASP.NET Core</param>
        /// <returns></returns>
        public async Task InvokeAsync(HttpContext httpContext, AzureAdSettings settings)
        {
            if (httpContext.User != null && httpContext.User.Identity != null && httpContext.User.Identity.IsAuthenticated)
            {
                var permissionsClaim = httpContext.User.Claims.SingleOrDefault(c => c.Type == PermissionConstants.PackedPermissionClaimType);
                if(permissionsClaim != null)
                {
                    await _next(httpContext).ConfigureAwait(false);
                    return;
                }

                string userId = httpContext.User.FindFirstValue(settings.UserIdClaimName);
                var email = httpContext.User.FindFirstValue(settings.EmailClaimName);

                var authPUserService =
                    httpContext.RequestServices.GetRequiredService<IAuthUsersAdminService>();

                var findStatus = await authPUserService.FindAuthUserByUserIdAsync(userId);
                if (findStatus.Result == null)
                {
                    //no user of that name found
                    var logger = httpContext.RequestServices.GetRequiredService<ILogger<AzureAdClaimApiMiddleware>>();

                    if (settings.AddNewUserIfNotPresent)
                    {
                        var username = httpContext.User.FindFirstValue(settings.UsernameClaimName);
                        if (username == null || username == "unknown")
                            username = email;

                        var createStatus = await authPUserService.AddNewUserAsync(userId, email, username, new List<string>());
                        createStatus.IfErrorsTurnToException();

                        logger.LogInformation($"Added a new user with UserId = {userId} on login.");
                    }
                    else
                    {
                        logger.LogWarning($"A user with UserId = {userId} logged in, but was not in the AuthP user database.");
                    }

                    //We replace some of the claims in the ClaimPrincipal so that the claims match what AuthP expects
                    CreateClaimPrincipalWithAuthPClaims(httpContext, userId, email);
                }
                else
                {
                    //We have an existing AuthP user, so we add their claims
                    var claimsCalculator =
                        httpContext.RequestServices.GetRequiredService<IClaimsCalculator>();

                    CreateClaimPrincipalWithAuthPClaims(httpContext, userId, email, await claimsCalculator.GetClaimsForAuthUserAsync(userId));
                }

            }
            await _next(httpContext).ConfigureAwait(false);
        }
        private static void CreateClaimPrincipalWithAuthPClaims(HttpContext ctx,
            string userId, string email, List<Claim> claimsToAdd = null)
        {
            var updatedClaims = ctx.User.Claims.ToList();

            if (claimsToAdd != null)
                //add the AuthP claims
                updatedClaims.AddRange(claimsToAdd);

            //NOTE: The ClaimTypes.NameIdentifier is expected to contain the UserId, but with AzureId you get another value
            //Therefore we remove/replace the NameIdentifier claim to have the user's id
            updatedClaims.Remove(
                updatedClaims.SingleOrDefault(x => x.Type == ClaimTypes.NameIdentifier));
            updatedClaims.Add(new Claim(ClaimTypes.NameIdentifier, userId));

            //NOTE: We need to provide the Name claim to get the correct name shown in the ASP.NET Core sign in/sign out display
            if(email != null)
                updatedClaims.Add(new Claim(ClaimTypes.Name, email));

            //now we create a new ClaimsIdentity to replace the existing Principal
            var appIdentity = new ClaimsIdentity(updatedClaims, ctx.User.Identity.AuthenticationType);
            ctx.User = new ClaimsPrincipal(appIdentity);
        }
    }
}
