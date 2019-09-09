using System;
using System.Collections.Generic;
using System.Text;

namespace VirtoCommerce.Storefront.Model.Security
{
    public class SendVerificationCodeResult
    {
        public bool? Succeeded { get; set; }
        public string Error { get; set; }
    }
}
