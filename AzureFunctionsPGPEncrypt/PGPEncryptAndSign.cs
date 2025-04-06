using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using System.Text;
using PgpCore;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;

namespace AzureFunctionsPGPEncrypt;

public class PGPEncryptAndSign
{
    private readonly ILogger<PGPEncryptAndSign> _logger;
    private readonly IConfiguration _configuration;

    public PGPEncryptAndSign(ILogger<PGPEncryptAndSign> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    [Function(nameof(PGPEncryptAndSign))]
    public async Task<IActionResult> RunAsync([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
    {
        _logger.LogInformation($"C# HTTP trigger function {nameof(PGPEncryptAndSign)} processed a request.");

        string publicKeyBase64 = _configuration["pgp-public-key"];
        string privateKeySignBase64 = _configuration["pgp-private-key-sign"];
        string passPhraseSign = _configuration["pgp-passphrase-sign"] ?? string.Empty;

        if (string.IsNullOrEmpty(publicKeyBase64))
        {
            return new BadRequestObjectResult($"Please add a base64 encoded public key to an environment variable called pgp-public-key");
        }

        if (string.IsNullOrEmpty(privateKeySignBase64))
        {
            return new BadRequestObjectResult($"Please add a base64 encoded private key to an environment variable called pgp-private-key-sign");
        }

        byte[] publicKeyBytes = Convert.FromBase64String(publicKeyBase64);
        string publicKey = Encoding.UTF8.GetString(publicKeyBytes);

        byte[] privateKeySignBytes = Convert.FromBase64String(privateKeySignBase64);
        string privateKeySign = Encoding.UTF8.GetString(privateKeySignBytes);

        var inputStream = new MemoryStream();
        await req.Body.CopyToAsync(inputStream);
        inputStream.Seek(0, SeekOrigin.Begin);

        string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
        dynamic data = JsonConvert.DeserializeObject(requestBody);
        string passPhraseFromRequest = data?.passPhrase;

        try
        {
            Stream encryptedData = await EncryptAndSignAsync(inputStream, publicKey, privateKeySign, passPhraseSign);
            return new OkObjectResult(encryptedData);
        }
        catch (PgpException pgpException)
        {
            return new BadRequestObjectResult(pgpException.Message);
        }
    }

    private async Task<Stream> EncryptAndSignAsync(Stream inputStream, string publicKey, string privateKey, string passPhrase)
    {
        EncryptionKeys encryptionKeys = string.IsNullOrEmpty(passPhrase)
            ? new EncryptionKeys(publicKey,privateKey)
            : new EncryptionKeys(publicKey, privateKey, passPhrase);

        using (PGP pgp = new PGP(encryptionKeys))
        {
            var outputStream = new MemoryStream();

            using (inputStream)
            {
                await pgp.EncryptStreamAndSignAsync(inputStream, outputStream, true, true);
                outputStream.Seek(0, SeekOrigin.Begin);
                return outputStream;
            }
        }
    }
}