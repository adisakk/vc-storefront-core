using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using VirtoCommerce.Storefront.AutoRestClients.PlatformModuleApi;
using VirtoCommerce.Storefront.AutoRestClients.PlatformModuleApi.Models;
using VirtoCommerce.Storefront.Domain;
using VirtoCommerce.Storefront.Domain.Common;
using VirtoCommerce.Storefront.Domain.Security;
using VirtoCommerce.Storefront.Domain.Security.Notifications;
using VirtoCommerce.Storefront.Infrastructure;
using VirtoCommerce.Storefront.Model;
using VirtoCommerce.Storefront.Model.Common;
using VirtoCommerce.Storefront.Model.Common.Events;
using VirtoCommerce.Storefront.Model.Common.Notifications;
using VirtoCommerce.Storefront.Model.Customer;
using VirtoCommerce.Storefront.Model.Customer.Services;
using VirtoCommerce.Storefront.Model.Security;
using VirtoCommerce.Storefront.Model.Security.Events;

namespace VirtoCommerce.Storefront.Controllers.Api
{
    [StorefrontApiRoute("account")]
    [ResponseCache(CacheProfileName = "None")]
    public class ApiAccountController : StorefrontControllerBase
    {
        private readonly IEventPublisher _publisher;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IMemberService _memberService;
        private readonly INotifications _platformNotificationApi;
        private readonly IAuthorizationService _authorizationService;
        private readonly ISecurity _security;
        private readonly IAssets _assets;

        public ApiAccountController(IWorkContextAccessor workContextAccessor, IStorefrontUrlBuilder urlBuilder, UserManager<User> userManager, SignInManager<User> signInManager, IAuthorizationService authorizationService,
        IMemberService memberService, IEventPublisher publisher, INotifications platformNotificationApi, ISecurity security, IAssets assets)
            : base(workContextAccessor, urlBuilder)
        {
            _userManager = userManager;
            _memberService = memberService;
            _publisher = publisher;
            _platformNotificationApi = platformNotificationApi;
            _authorizationService = authorizationService;
            _signInManager = signInManager;
            _security = security;
            _assets = assets;
        }

        // GET: storefrontapi/account
        [HttpGet]
        [AllowAnonymous]
        public ActionResult<User> GetCurrentUser()
        {
            return WorkContext.CurrentUser;
        }

        /// <summary>
        /// // GET: storefrontapi/account/{userId}
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        [HttpGet("{userId}")]
        [Authorize(SecurityConstants.Permissions.CanViewUsers)]
        public async Task<ActionResult<User>> GetUserById(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null && !string.IsNullOrEmpty(user.ContactId))
            {
                var authorizationResult = await _authorizationService.AuthorizeAsync(User, user?.Contact?.Organization, CanEditOrganizationResourceAuthorizeRequirement.PolicyName);
                if (!authorizationResult.Succeeded)
                {
                    return Unauthorized();
                }
            }
            return user;
        }

        // DELETE: storefrontapi/account/{userId}
        [HttpDelete("{userId}")]
        [Authorize(SecurityConstants.Permissions.CanDeleteUsers)]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<IdentityResult>> DeleteUser([FromRoute] string userId)
        {
            //TODO: Authorization check
            var result = IdentityResult.Success;
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var authorizationResult = await _authorizationService.AuthorizeAsync(User, user?.Contact?.Organization, CanEditOrganizationResourceAuthorizeRequirement.PolicyName);
                if (!authorizationResult.Succeeded)
                {
                    return Unauthorized();
                }

                result = await _userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    await _publisher.Publish(new UserDeletedEvent(WorkContext, user));
                }
            }
            return result;
        }

        // POST: storefrontapi/account/organization
        [HttpPost("organization")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<IdentityResult>> RegisterOrganization([FromBody] OrganizationRegistration orgRegistration)
        {
            var result = IdentityResult.Success;

            TryValidateModel(orgRegistration);

            if (ModelState.IsValid)
            {
                var organization = orgRegistration.ToOrganization();
                organization = await _memberService.CreateOrganizationAsync(organization);
                var contact = orgRegistration.ToContact();
                contact.OrganizationId = organization.Id;

                var user = orgRegistration.ToUser();
                user.Contact = contact;
                user.StoreId = WorkContext.CurrentStore.Id;
                user.Roles = new[] { SecurityConstants.Roles.OrganizationMaintainer };

                result = await _userManager.CreateAsync(user, orgRegistration.Password);
                if (result.Succeeded)
                {
                    user = await _userManager.FindByNameAsync(user.UserName);
                    await _publisher.Publish(new UserRegisteredEvent(WorkContext, user, orgRegistration));
                    await _signInManager.SignInAsync(user, isPersistent: true);
                    await _publisher.Publish(new UserLoginEvent(WorkContext, user));
                }
            }
            else
            {
                result = IdentityResult.Failed(ModelState.Values.SelectMany(x => x.Errors).Select(x => new IdentityError { Description = x.ErrorMessage }).ToArray());
            }

            return result;
        }

        // POST: storefrontapi/account/user
        [HttpPost("user")]
        [Authorize(SecurityConstants.Permissions.CanCreateUsers)]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<IdentityResult>> RegisterUser([FromBody] OrganizationUserRegistration registration)
        {
            var result = IdentityResult.Success;

            TryValidateModel(registration);

            if (ModelState.IsValid)
            {
                //Allow to register new users only within own organization
                var authorizationResult = await _authorizationService.AuthorizeAsync(User, new Organization { Id = registration.OrganizationId }, CanEditOrganizationResourceAuthorizeRequirement.PolicyName);
                if (!authorizationResult.Succeeded)
                {
                    return Unauthorized();
                }

                var contact = registration.ToContact();
                contact.OrganizationId = registration.OrganizationId;

                var user = registration.ToUser();
                user.Contact = contact;
                user.StoreId = WorkContext.CurrentStore.Id;

                result = await _userManager.CreateAsync(user, registration.Password);
                if (result.Succeeded)
                {
                    user = await _userManager.FindByNameAsync(user.UserName);
                    await _publisher.Publish(new UserRegisteredEvent(WorkContext, user, registration));
                }
            }
            else
            {
                result = IdentityResult.Failed(ModelState.Values.SelectMany(x => x.Errors).Select(x => new IdentityError { Description = x.ErrorMessage }).ToArray());
            }
            return result;
        }

        // POST: storefrontapi/account/invitation
        [HttpPost("invitation")]
        [ValidateAntiForgeryToken]
        [ProducesResponseType(401)]
        public async Task<ActionResult<IdentityResult>> CreateUserInvitation([FromBody] UsersInvitation invitation)
        {
            var result = IdentityResult.Success;
            TryValidateModel(invitation);

            if (ModelState.IsValid)
            {
                var organizationId = WorkContext.CurrentUser?.Contact?.Organization?.Id;
                //If it is organization invitation need to check authorization for this action
                if (!string.IsNullOrEmpty(organizationId))
                {
                    var authorizationResult = await _authorizationService.AuthorizeAsync(User, null, SecurityConstants.Permissions.CanInviteUsers);
                    if (!authorizationResult.Succeeded)
                    {
                        return Unauthorized();
                    }
                }

                foreach (var email in invitation.Emails)
                {
                    var user = await _userManager.FindByEmailAsync(email);
                    if (user == null)
                    {
                        user = new User
                        {
                            UserName = email,
                            StoreId = WorkContext.CurrentStore.Id,
                            Email = email,
                        };
                        var roles = invitation.Roles?.Select(x => new Model.Security.Role { Id = x }).ToList();
                        //Add default role for organization member invitation
                        if (roles.IsNullOrEmpty() && !string.IsNullOrEmpty(organizationId))
                        {
                            roles = new[] { SecurityConstants.Roles.OrganizationEmployee }.ToList();
                        }
                        user.Roles = roles;
                        result = await _userManager.CreateAsync(user);
                    }

                    if (result.Succeeded)
                    {
                        user = await _userManager.FindByNameAsync(user.UserName);
                        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                        var callbackUrl = Url.Action("ConfirmInvitation", "Account", new { OrganizationId = organizationId, user.Email, Token = token }, Request.Scheme, host: WorkContext.CurrentStore.Host);
                        var inviteNotification = new RegistrationInvitationNotification(WorkContext.CurrentStore.Id, WorkContext.CurrentLanguage)
                        {
                            InviteUrl = callbackUrl,
                            Sender = WorkContext.CurrentStore.Email,
                            Recipient = user.Email
                        };
                        var sendingResult = await _platformNotificationApi.SendNotificationAsync(inviteNotification.ToNotificationDto());
                        if (sendingResult.IsSuccess != true)
                        {
                            var errors = result.Errors.Concat(new IdentityError[] { new IdentityError() { Description = sendingResult.ErrorMessage } }).ToArray();
                            result = IdentityResult.Failed(errors);
                        }
                    }
                }
            }
            else
            {
                result = IdentityResult.Failed(ModelState.Values.SelectMany(x => x.Errors).Select(x => new IdentityError { Description = x.ErrorMessage }).ToArray());
            }
            return result;
        }

        // PUT: storefrontapi/account/organization
        [HttpPut("organization")]
        [Authorize(SecurityConstants.Permissions.CanEditOrganization)]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> UpdateOrganization([FromBody] Organization organization)
        {
            //Allow to register new users only within own organization
            var authorizationResult = await _authorizationService.AuthorizeAsync(User, organization, CanEditOrganizationResourceAuthorizeRequirement.PolicyName);
            if (!authorizationResult.Succeeded)
            {
                return Unauthorized();
            }
            await _memberService.UpdateOrganizationAsync(organization);

            return Ok();
        }

        // GET: storefrontapi/account/organization/current
        [HttpGet("organization/current")]
        public ActionResult<Organization> GetCustomerOrganization()
        {
            var result = WorkContext.CurrentUser?.Contact?.Organization;
            return result;
        }

        // POST: storefrontapi/account/organization/users/search
        [HttpPost("organization/users/search")]
        [Authorize(SecurityConstants.Permissions.CanViewUsers)]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<UserSearchResult>> SearchOrganizationUsersAsync([FromBody] OrganizationContactsSearchCriteria searchCriteria)
        {
            searchCriteria.OrganizationId = searchCriteria.OrganizationId ?? WorkContext.CurrentUser?.Contact?.Organization?.Id;
            //Allow to register new users only within own organization
            var authorizationResult = await _authorizationService.AuthorizeAsync(User, new Organization { Id = searchCriteria.OrganizationId }, CanEditOrganizationResourceAuthorizeRequirement.PolicyName);
            if (!authorizationResult.Succeeded)
            {
                return Unauthorized();
            }
            if (searchCriteria.OrganizationId != null)
            {
                var contactsSearchResult = await _memberService.SearchOrganizationContactsAsync(searchCriteria);
                var userIds = contactsSearchResult.Select(x => x.SecurityAccounts?.FirstOrDefault()).OfType<SecurityAccount>().Select(x => x.Id);
                var users = new List<User>();
                foreach (var userId in userIds)
                {
                    var user = await _userManager.FindByIdAsync(userId);
                    if (user != null)
                    {
                        users.Add(user);
                    }
                }
                return new UserSearchResult
                {
                    TotalCount = contactsSearchResult.TotalItemCount,
                    Results = users
                };
            }
            return Ok();
        }

        // POST: storefrontapi/account/{userId}/lock
        [HttpPost("{userId}/lock")]
        [Authorize(SecurityConstants.Permissions.CanEditUsers)]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<IdentityResult>> LockUser([FromRoute]string userId)
        {
            //TODO: Add authorization checks
            var result = IdentityResult.Success;
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                //Allow to register new users only within own organization
                var authorizationResult = await _authorizationService.AuthorizeAsync(User, user?.Contact?.Organization, CanEditOrganizationResourceAuthorizeRequirement.PolicyName);
                if (!authorizationResult.Succeeded)
                {
                    return Unauthorized();
                }

                await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.MaxValue);
            }
            return result;
        }

        // POST: storefrontapi/account/{userId}/unlock
        [HttpPost("{userId}/unlock")]
        [Authorize(SecurityConstants.Permissions.CanEditUsers)]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<IdentityResult>> UnlockUser([FromRoute] string userId)
        {
            //TODO: Add authorization checks
            var result = IdentityResult.Success;
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                //Allow to register new users only within own organization
                var authorizationResult = await _authorizationService.AuthorizeAsync(User, user?.Contact?.Organization, CanEditOrganizationResourceAuthorizeRequirement.PolicyName);
                if (!authorizationResult.Succeeded)
                {
                    return Unauthorized();
                }
                await _userManager.ResetAccessFailedCountAsync(user);
                await _userManager.SetLockoutEndDateAsync(user, null);
            }
            return result;
        }

        private void SetContactDynamicProperty (string name, string value, Contact contact)
        {
            var property = contact.DynamicProperties.FirstOrDefault(x => x.Name == name);
            if (property.Values.FirstOrDefault() == null)
            {
                property.Values.Add(new LocalizedString() { Value = value });
            }
            else
            {
                property.Values.FirstOrDefault().Value = value;
            }
        }

        // POST: storefrontapi/account
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ProducesResponseType(401)]
        public async Task<ActionResult> UpdateAccount([FromBody] UserUpdateInfo userUpdateInfo)
        {
            //TODO:Check authorization
            if (string.IsNullOrEmpty(userUpdateInfo.Id))
            {
                userUpdateInfo.Id = WorkContext.CurrentUser.Id;
            }
            var isSelfEditing = userUpdateInfo.Id == WorkContext.CurrentUser.Id;


            if (!string.IsNullOrEmpty(userUpdateInfo.Id))
            {
                var user = await _userManager.FindByIdAsync(userUpdateInfo.Id);
                if (user != null)
                {
                    if (!isSelfEditing)
                    {
                        var authorizationResult = await _authorizationService.AuthorizeAsync(User, null, SecurityConstants.Permissions.CanEditUsers);
                        if (authorizationResult.Succeeded)
                        {
                            authorizationResult = await _authorizationService.AuthorizeAsync(User, user?.Contact?.Organization, CanEditOrganizationResourceAuthorizeRequirement.PolicyName);
                        }
                        if (!authorizationResult.Succeeded)
                        {
                            return Unauthorized();
                        }
                        //Doesn't allow change self roles
                        user.Roles = userUpdateInfo.Roles?.Select(x => new Model.Security.Role { Id = x });
                    }

                    if (user.Contact != null)
                    {
                        user.Contact.FirstName = userUpdateInfo.FirstName;
                        user.Contact.LastName = userUpdateInfo.LastName;
                        user.Contact.FullName = userUpdateInfo.FullName;
                    }

                    user.Email = userUpdateInfo.Email;

                    await _userManager.UpdateAsync(user);

                    if (user.Contact != null && !string.IsNullOrEmpty(user.Contact.Id))
                    {
                        var contact = await _memberService.GetContactByIdAsync(user.Contact.Id);

                        SetContactDynamicProperty("Sex", userUpdateInfo.Gender, contact);
                        SetContactDynamicProperty("Birthday", userUpdateInfo.Birthday, contact);
                        SetContactDynamicProperty("IdCardNumber", userUpdateInfo.IdCardNumber, contact);
                        SetContactDynamicProperty("IdCardPhoto", userUpdateInfo.IdCardPhoto, contact);
                        SetContactDynamicProperty("BankbookPhoto", userUpdateInfo.BankbookPhoto, contact);
                        
                        await _memberService.UpdateContactAsync(contact);
                    }
                }
            }
            return Ok();
        }

        // POST: storefrontapi/account/password
        [HttpPost("password")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<PasswordChangeResult>> ChangePassword([FromBody] ChangePassword formModel)
        {
            var changePassword = new ChangePasswordInfo
            {
                OldPassword = formModel.OldPassword,
                NewPassword = formModel.NewPassword,
            };

            var result = await _userManager.ChangePasswordAsync(WorkContext.CurrentUser, formModel.OldPassword, formModel.NewPassword);

            return new PasswordChangeResult { Succeeded = result.Succeeded, Errors = result.Errors.Select(x => new FormError { Code = x.Code.PascalToKebabCase(), Description = x.Description }).ToList() };
        }

        // POST: storefrontapi/account/checkpassword
        [HttpPost("checkpassword")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<PasswordCheckResult>> CheckPassword([FromBody] CheckPassword checkPassword)
        {
            var user = await _userManager.FindByIdAsync(WorkContext.CurrentUser.Id);
            var result = await _userManager.CheckPasswordAsync(user, checkPassword.CurrentPassword);

            return new PasswordCheckResult { IsValid = result};
        }

        // POST: storefrontapi/account/addresses
        [HttpPost("addresses")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> UpdateAddresses([FromBody] IList<Address> addresses)
        {
            await _memberService.UpdateContactAddressesAsync(WorkContext.CurrentUser.ContactId, addresses);

            return Ok();
        }

        // DELETE: storefrontapi/account/phonenumber
        [HttpDelete("phonenumber")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<RemovePhoneNumberResult>> RemovePhoneNumber()
        {
            var twoFactorAuthEnabled = await _signInManager.UserManager.GetTwoFactorEnabledAsync(WorkContext.CurrentUser);
            if (twoFactorAuthEnabled)
            {
                return Forbid();
            }

            var result = await _signInManager.UserManager.SetPhoneNumberAsync(WorkContext.CurrentUser, null);
            await _signInManager.SignInAsync(WorkContext.CurrentUser, isPersistent: false);

            return new RemovePhoneNumberResult { Succeeded = result.Succeeded, Errors = result.Errors.Select(x => x.Description) };
        }

        // POST: storefrontapi/account/twofactorauthentification
        [HttpPost("twofactorauthentification")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<ChangeTwoFactorAuthenticationResult>> ChangeTwoFactorAuthentication([FromBody] ChangeTwoFactorAuthenticationModel model)
        {
            if (model.Enabled)
            {
                var phoneConfirmed = await _signInManager.UserManager.IsPhoneNumberConfirmedAsync(WorkContext.CurrentUser);
                if (!phoneConfirmed)
                {
                    var url = "/account/phonenumber";

                    return new ChangeTwoFactorAuthenticationResult { Succeeded = false, VerificationUrl = url };
                }
            }

            var result = await _signInManager.UserManager.SetTwoFactorEnabledAsync(WorkContext.CurrentUser, model.Enabled);
            await _signInManager.SignInAsync(WorkContext.CurrentUser, isPersistent: false);

            return new ChangeTwoFactorAuthenticationResult { Succeeded = result.Succeeded, Errors = result.Errors.Select(x => x.Description) };
        }

        // POST: storefrontapi/account/phonenumber
        [HttpPost("phonenumber")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<UpdatePhoneNumberResult>> UpdatePhoneNumber([FromBody] UpdatePhoneNumberModel model)
        {
            TryValidateModel(model);

            if (!ModelState.IsValid)
            {
                return new UpdatePhoneNumberResult { Succeeded = false, Error = "Phone number is not valid" };
            }

            var code = await _signInManager.UserManager.GenerateChangePhoneNumberTokenAsync(WorkContext.CurrentUser, model.PhoneNumber);
            var result = await _signInManager.UserManager.ChangePhoneNumberAsync(WorkContext.CurrentUser, model.PhoneNumber, code);
            await _signInManager.SignInAsync(WorkContext.CurrentUser, isPersistent: false);

            return new UpdatePhoneNumberResult { Succeeded = result.Succeeded };

        }

        // POST: storefrontapi/account/verificationcode
        [HttpPost("verificationcode")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<SendVerificationCodeResult>> SendVerificationCode([FromBody] SendVerificationCodeModel model)
        {
           var result = new SendNotificationResult();

            if (!string.IsNullOrEmpty(model.PhoneNumber))
            {
                //Sending OTP to the given phone number via SMS service
                var number = "+66" + model.PhoneNumber; // TODO Country code should be read from db for specific user location
                try
                {
                    NotificationBase notification = new TwoFactorSmsNotification(WorkContext.CurrentStore.Id, WorkContext.CurrentLanguage)
                    {
                        Token = await _security.GenerateOnetimePasswordAsync(model.PhoneNumber),
                        Recipient = number
                    };

                    result = await _platformNotificationApi.SendNotificationAsync(notification.ToNotificationDto());
                }
                catch
                {
                    result.IsSuccess = false;
                    result.ErrorMessage = "Error occurred while sending SMS notification to "+number;
                }
            } else
            {
                //Sending OTP to the given email address via SMTP
                try
                {
                    NotificationBase notification = new TwoFactorEmailNotification(WorkContext.CurrentStore.Id, WorkContext.CurrentLanguage)
                    {
                        Token = await _security.GenerateOnetimePasswordAsync(model.Email),
                        Sender = WorkContext.CurrentStore.Email,
                        Recipient = model.Email
                    };

                    result = await _platformNotificationApi.SendNotificationAsync(notification.ToNotificationDto());
                }
                catch
                {
                    result.IsSuccess = false;
                    result.ErrorMessage = "Error occurred while sending Email notification to "+model.Email;
                }
            }

            

            return new SendVerificationCodeResult { Succeeded = true }; //TODO Always return true for testing purpose

        }

        // POST: storefrontapi/account/validatecode
        [HttpPost("validatecode")]
        [ValidateAntiForgeryToken]
        public ActionResult<ValidateVerificationCodeResult> ValidateVerificationCode([FromBody] ValidateVerificationCodeModel model)
        {
            var result = false;

            try
            {
                result = _security.ValidateOnetimePassword(model.Recipient, model.VerificationCode).Value;
            }
            catch
            {
                result = false;
            }

            return new ValidateVerificationCodeResult { Succeeded = result };

        }

        // POST: storefrontapi/account/email
        [HttpPost("email")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult<UpdateEmailAddressResult>> UpdateEmail([FromBody] UpdateEmailAddressModel model)
        {
            TryValidateModel(model);

            if (!ModelState.IsValid)
            {
                return new UpdateEmailAddressResult { Succeeded = false, Error = "Email address is not valid" };
            }

            var user = await _userManager.FindByIdAsync(WorkContext.CurrentUser.Id);
            if (user == null)
            {
                return new UpdateEmailAddressResult { Succeeded = false, Error = "Database error" };
            }

            user.Email = model.Email;
            var update = await _userManager.UpdateAsync(user);

            return new UpdateEmailAddressResult() { Succeeded = update.Succeeded};
        }

        // POST: storefrontapi/account/upload
        [HttpPost("upload")]
        public async Task<ActionResult<BlobInfo>> Upload([FromForm] IFormFile file)
        {
            var folder = "documents/" + WorkContext.CurrentUser.Id;

            var result = await _assets.UploadAssetAsync(folder, null, file.FileName, file.OpenReadStream());
            return Ok(result);
        }
    }
}
