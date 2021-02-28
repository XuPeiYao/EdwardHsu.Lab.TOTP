using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

using OtpNet;

using QRCoder;

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

using XPY.ToolKit.Utilities.Cryptography;

namespace EdwardHsu.Lab.TOTP.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TotpController : ControllerBase
    {

        private readonly ILogger<TotpController> _logger;
        private static byte[] secretKey;

        public TotpController(ILogger<TotpController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        public IActionResult GetToptQRCode()
        {
            if (secretKey == null)
            {
                secretKey = KeyGeneration.GenerateRandomKey();
            }

            UriBuilder uriBuilder = new UriBuilder();
            uriBuilder.Scheme = "otpauth";
            uriBuilder.Host = "totp";
            uriBuilder.Path = "TOTP DEMO APP";

            var query = new Dictionary<string, string>();
            query.Add("secret", Base32Encoding.ToString(secretKey));
            query.Add("issuer", "Edward Hsu DEMO APP");

            var uri = uriBuilder.ToString();
            uri = QueryHelpers.AddQueryString(uri, query);

            QRCodeGenerator qrGenerator = new QRCodeGenerator();
            QRCodeData qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
            QRCode qrCode = new QRCode(qrCodeData);
            Bitmap qrCodeImage = qrCode.GetGraphic(5);

            using var stream = new MemoryStream();
            qrCodeImage.Save(stream, System.Drawing.Imaging.ImageFormat.Png);

            return File(stream.ToArray(), "image/png");
        }

        [HttpPost]
        public async Task<bool> VerifyTopt(string code)
        {
            var totp = new Totp(secretKey);
            return totp.VerifyTotp(code, out _);
        }
    }
}
