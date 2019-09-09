using System;
using System.Collections.Generic;
using VirtoCommerce.Storefront.Model.Common;

namespace VirtoCommerce.Storefront.Model.Security
{
    public partial class UserUpdateInfo : Entity
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string FullName { get; set; }
        public string Email { get; set; }
        public IList<string> Roles { get; set; }

        public string Birthday { get; set; }
        public string Gender { get; set; }
        public string IdCardNumber { get; set; }
        public string IdCardPhoto { get; set; }
        public string BankbookPhoto { get; set; }
    }
}
