using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace VirtoCommerce.Storefront.Model.Security
{
    public class UpdateEmailAddressResult
    {
        public bool? Succeeded { get; set; }
        public string Error { get; set; }
    }
}
