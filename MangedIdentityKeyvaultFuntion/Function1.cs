using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace MangedIdentityKeyvaultFuntion
{
    public static class Function1
    {
        [FunctionName("Function1")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string name = req.Query["name"];

            //var credential = new ClientSecretCredential("231dd9cd-ddc7-4fba-ae78-9f4ac3c912e7", "5f43fe5c-1c2b-4afa-97e6-fda41302e28b", "5ZlLakKHA:DE.6Jq-GbJWF=icJaCwW32");
            var credential = new ManagedIdentityCredential();
            var kvUri = "https://kvswapana.vault.azure.net/";

            var secretClient = new SecretClient(new Uri(kvUri), credential);
            var encryptedDEK = secretClient.GetSecret("DEK");
            var keyClient = new KeyClient(new Uri(kvUri), credential);
            var encryptedKEY = keyClient.GetKey("KEK");
            var cryptoClient = new CryptographyClient(encryptedKEY.Value.Id, credential);
            DecryptResult decryptDek = cryptoClient.Decrypt(EncryptionAlgorithm.RsaOaep256, Convert.FromBase64String(encryptedDEK.Value.Value));

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;

            return name != null
            // Create MemoryStream    
                ? (ActionResult)new OkObjectResult($"Hello, {name}, {encryptedKEY.Value.Id}, {Encoding.UTF8.GetString(decryptDek.Plaintext)}")
                : new BadRequestObjectResult("Please pass a name on the query string or in the request body");
        }
    }
}
