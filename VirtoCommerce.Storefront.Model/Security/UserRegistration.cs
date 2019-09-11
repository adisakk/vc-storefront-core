using System;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace VirtoCommerce.Storefront.Model.Security
{
    public partial class UserRegistration 
    {
        public UserRegistration()
        {
            VerificationType = "Phone"; // Phone or Email
            VerificationCodeSent = false;
            VerificationSucceeded = false;
            CustomerType = "Individual";
        }

        [FromForm(Name = "customer[verification_succeeded]")]
        public bool VerificationSucceeded { get; set; }

        [FromForm(Name = "customer[verification_code_sent]")]
        public bool VerificationCodeSent { get; set; }

        [FromForm(Name = "customer[verification_type]")]
        public string VerificationType { get; set; }

        [FromForm(Name = "customer[verification_code]")]
        public string VerificationCode { get; set; }

        [FromForm(Name = "customer[phone_number]")]
        [Phone]
        public string PhoneNumber { get; set; }

        [FromForm(Name = "customer[photoUrl]")]
        public string PhotoUrl { get; set; }

        [FromForm(Name = "customer[first_name]")]
        public string FirstName { get; set; }

        [FromForm(Name = "customer[full_name]")]
        public string FullName { get; set; }

        [FromForm(Name = "customer[last_name]")]
        public string LastName { get; set; }

        [FromForm(Name = "customer[email]")]
        [EmailAddress]
        public string Email { get; set; }

        [FromForm(Name = "customer[user_name]")]
        public string UserName { get; set; }

        [FromForm(Name = "customer[password]")]
        public string Password { get; set; }

        [FromForm(Name = "customer[store_id]")]
        public string StoreId { get; set; }

        [FromForm(Name = "customer[name]")]
        public string Name { get; set; }

        [FromForm(Name = "customer[customer_type]")]
        public string CustomerType { get; set; }

        [FromForm(Name = "customer[address]")]
        public Address Address { get; set; }
        [FromForm(Name = "customer[salutation]")]
        public string Salutation { get; set; }
        [FromForm(Name = "customer[middleName]")]
        public string MiddleName { get; set; }
        [FromForm(Name = "customer[birthDate]")]
        public DateTime? BirthDate { get; set; }
        [FromForm(Name = "customer[timeZone]")]
        public string TimeZone { get; set; }     
      
    }
}
