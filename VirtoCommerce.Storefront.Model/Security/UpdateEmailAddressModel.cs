using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace VirtoCommerce.Storefront.Model.Security
{
    public class UpdateEmailAddressModel
    {
        [Required]
        [FromForm(Name = "customer[email]")]
        [EmailAddress]
        public string Email { get; set; }
    }
}
