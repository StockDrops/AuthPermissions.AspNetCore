﻿// Copyright (c) 2021 Jon P Smith, GitHub: JonPSmith, web: http://www.thereformedprogrammer.net/
// Licensed under MIT license. See License.txt in the project root for license information.

using System.Collections.Generic;
using AuthPermissions.SetupCode;

namespace Example5.MvcWebApp.AzureAdB2C.PermissionCode
{
    public static class Example5AppAuthSetupData
    {
        public const string BulkLoadRolesWithPermissions = @"
SuperAdmin | Super admin - only use for setup|: AccessAll,
Admin Role | Overall app Admin |: UserRead, UserSync, UserChange, UserRolesChange, UserChangeTenant, UserRemove, RoleRead, RoleChange, PermissionRead

Basic Role | Normal User |: BasicFeature";


        public static readonly List<DefineUserWithRolesTenant> UsersRolesDefinition = new List<DefineUserWithRolesTenant>
        {
            new DefineUserWithRolesTenant("Test@authpermissions.onmicrosoft.com", "Test User", "Basic Role", 
                "0ee0f6cb-4a2e-4aaf-8e4b-dc0c4cd01613"),
            new DefineUserWithRolesTenant("Admin@authpermissions.onmicrosoft.com", "Admin User", "Admin Role",
                "a5a10d86-27cf-4fff-8bdd-ca6ee9c93f27"),
        };
    }
}