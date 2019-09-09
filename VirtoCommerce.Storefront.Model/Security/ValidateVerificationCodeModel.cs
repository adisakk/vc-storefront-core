using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace VirtoCommerce.Storefront.Model.Security
{
    public class ValidateVerificationCodeModel
    {
        [Required]
        [FromForm(Name = "customer[recipient]")]
        [Phone]
        public string Recipient { get; set; }

        [Required]
        [FromForm(Name = "customer[verificationcode]")]
        [Phone]
        public string VerificationCode { get; set; }
    }
}
