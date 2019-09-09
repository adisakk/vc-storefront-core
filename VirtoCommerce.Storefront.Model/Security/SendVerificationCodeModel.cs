using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace VirtoCommerce.Storefront.Model.Security
{
    public class SendVerificationCodeModel
    {
        [FromForm(Name = "customer[phoneNumber]")]
        [Phone]
        public string PhoneNumber { get; set; }

        [FromForm(Name = "customer[email]")]
        [EmailAddress]
        public string Email { get; set; }
    }
}
