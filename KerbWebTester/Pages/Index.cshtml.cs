using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Serialization;

namespace KerbWebTester.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;

        public IndexModel(ILogger<IndexModel> logger)
        {
            _logger = logger;
        }

        private void Setup()
        {
            ViewData["SPN"] = $"http/{Request.Host.Value}";
        }

        public async Task OnGet()
        {
            Setup();

            if (!Request.Query.ContainsKey("decode"))
            {
                return;
            }

            var encryptedPassword = Request.Query["key"].FirstOrDefault();
            var realm = Request.Query["realm"].FirstOrDefault();
            var name = Request.Query["name"].FirstOrDefault();

            try
            {
                await DoNegotiateLoop(encryptedPassword, name, realm);
            }
            catch (NotSupportedException ex)
            {
                ViewData["Error"] = ex.Message;
            }
        }

        private async Task DoNegotiateLoop(string encryptedPassword, string name, string realm)
        {
            if (!Request.Headers.TryGetValue("Authorization", out StringValues authzHeader))
            {
                Response.Headers.Add("WWW-Authenticate", "Negotiate");
                Response.StatusCode = 401;

                return;
            }

            if (!string.IsNullOrWhiteSpace(encryptedPassword))
            {
                await DecodeTicket(authzHeader.First(), encryptedPassword, name, realm);

                return;
            }

            DumpTicket(authzHeader.First());

            ;
        }

        private void DumpTicket(string ticket)
        {
            ticket = RemoveNegotiate(ticket);

            var ticketBytes = Convert.FromBase64String(ticket);

            var request = MessageParser.Parse(ticketBytes);

            ReadOnlyMemory<byte> mechToken = default;

            if (request is NegotiateContextToken nego)
            {
                mechToken = nego.Token.InitialToken.MechToken ?? default;
            }
            else if (request is NegotiationToken negoToken)
            {
                mechToken = negoToken.InitialToken.MechToken ?? default;
            }

            if (mechToken.Length > 0)
            {
                request = new
                {
                    Request = request,
                    Token = MessageParser.Parse(mechToken)
                };
            }

            var formatted = FormatSerialize(request);

            ViewData["Ticket"] = formatted;
        }

        private static string RemoveNegotiate(string ticket)
        {
            if (ticket.StartsWith("negotiate", StringComparison.InvariantCultureIgnoreCase))
            {
                ticket = ticket.Trim().Substring(9).Trim();
            }

            return ticket;
        }

        private async Task DecodeTicket(string ticket, string encryptedPassword, string name, string realm)
        {
            string decryptedKey = DecryptKey(encryptedPassword);

            var keys = new KeyTable(
                new KerberosKey(decryptedKey, new PrincipalName(PrincipalNameType.NT_PRINCIPAL, realm, new[] { name }))
            );

            var validator = new KerberosValidator(keys);

            ticket = RemoveNegotiate(ticket);

            var validated = await validator.Validate(Convert.FromBase64String(ticket));

            var authenticator = new KerberosAuthenticator(keys);

            var identity = await authenticator.Authenticate(ticket) as KerberosIdentity;

            var formatted = FormatSerialize(new
            {
                Decrypted = validated,
                Identity = new
                {
                    identity.Name,
                    identity.Restrictions,
                    identity.ValidationMode,
                    Claims = identity.Claims.Select(c => new { c.Type, c.Value })
                }
            });

            ViewData["Ticket"] = formatted;
        }

        private string DecryptKey(string encryptedPassword)
        {
            var bytes = Base64UrlDecode(encryptedPassword);

            var entropy = bytes.Take(16).ToArray();

            var encrypted = bytes.Skip(16).ToArray();

            var decrypted = ProtectedData.Unprotect(encrypted, entropy, DataProtectionScope.LocalMachine);

            return Encoding.UTF8.GetString(decrypted);
        }

        private string FormatSerialize(object obj)
        {
            var settings = new JsonSerializerSettings
            {
                Formatting = Formatting.Indented,
                Converters = new JsonConverter[] { new StringEnumArrayConverter(), new BinaryConverter() },
                ContractResolver = new KerberosIgnoreResolver()
            };

            return JsonConvert.SerializeObject(obj, settings);
        }

        public void OnPost()
        {
            Setup();

            var password = Request.Form["password"].FirstOrDefault();

            var name = Request.Form["name"].FirstOrDefault();

            var realm = Request.Form["realm"].FirstOrDefault();

            string encrypted = "";

            if (!string.IsNullOrWhiteSpace(password))
            {
                encrypted = EncryptKey(password);
            }

            Response.Redirect($"/?decode=true&key={encrypted}&name={name}&realm={realm}");
        }

        private string EncryptKey(string password)
        {
            var entropy = new byte[16];

            RandomNumberGenerator.Fill(entropy);

            var protectedData = ProtectedData.Protect(Encoding.UTF8.GetBytes(password), entropy, DataProtectionScope.LocalMachine);

            var bytes = entropy.Concat(protectedData).ToArray();

            return Base64UrlEncode(bytes);
        }

        static string Base64UrlEncode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg);

            s = s.Replace("=", "");
            s = s.Replace('+', '-');
            s = s.Replace('/', '_');

            return s;
        }

        static byte[] Base64UrlDecode(string arg)
        {
            string s = arg;

            s = s.Replace('-', '+');
            s = s.Replace('_', '/');

            switch (s.Length % 4)
            {
                case 0:
                    break;
                case 2:
                    s += "==";
                    break;
                case 3:
                    s += "=";
                    break;
            }

            return Convert.FromBase64String(s);
        }
    }

    internal class BinaryConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            Debug.WriteLine(objectType.Name);

            return objectType == typeof(ReadOnlyMemory<byte>) || objectType == typeof(ReadOnlyMemory<byte>?);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            throw new NotImplementedException();
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            ReadOnlyMemory<byte> mem = default;

            if (value.GetType() == typeof(ReadOnlyMemory<byte>))
            {
                mem = (ReadOnlyMemory<byte>)value;
            }
            else if (value.GetType() == typeof(ReadOnlyMemory<byte>))
            {
                var val = (ReadOnlyMemory<byte>?)value;

                if (val != null)
                {
                    mem = val.Value;
                }
            }

            writer.WriteValue(Convert.ToBase64String(mem.ToArray()));
        }
    }

    internal class StringEnumArrayConverter : StringEnumConverter
    {
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (value == null)
            {
                writer.WriteNull();
                return;
            }

            Enum e = (Enum)value;

            var enumVal = e.ToString().Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries);

            writer.WriteStartArray();

            foreach (var en in enumVal)
            {
                writer.WriteValue(en);
            }

            writer.WriteEndArray();
        }
    }

    internal class KerberosIgnoreResolver : DefaultContractResolver
    {
        protected override JsonProperty CreateProperty(MemberInfo member, MemberSerialization memberSerialization)
        {
            JsonProperty property = base.CreateProperty(member, memberSerialization);

            var attr = member.GetCustomAttribute<KerberosIgnoreAttribute>();

            if (attr != null)
            {
                property.Ignored = true;
            }

            return property;
        }
    }
}
