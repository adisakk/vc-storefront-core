using VirtoCommerce.Storefront.Model.Common;

namespace VirtoCommerce.Storefront.Model.Security
{
    public partial class CheckPassword : ValueObject
    {
        public string CurrentPassword { get; set; }
    }
}
