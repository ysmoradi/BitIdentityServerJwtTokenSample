using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BitIdentityServerJwtTokenSample
{
    class Program
    {
        static void Main(string[] args)
        {
            // 1- Create cert & pfx using following instructions:
            // https://stackoverflow.com/a/55378579/2720104

            // 2- Get public key from pfx (Don't give pfx file and its password to other people. They only need public key to validate jwt tokens)
            string publicKey = GetPublicKey();

            string valid_access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhCQzVDMjdFMkUxRDUwQzVGOEU2QTc4RjA0MjZGMDg5QTVDODdCQkUiLCJ4NXQiOiJpOFhDZmk0ZFVNWDQ1cWVQQkNid2lhWEllNzQiLCJ0eXAiOiJKV1QifQ.eyJuYmYiOjE2MDk0MTE1NTIsImV4cCI6MTYxMDAxNjM1MiwiaXNzIjoiQml0Q2hhbmdlU2V0TWFuYWdlciIsImF1ZCI6IkJpdENoYW5nZVNldE1hbmFnZXIvcmVzb3VyY2VzIiwiY2xpZW50X2lkIjoiQml0Q2hhbmdlU2V0TWFuYWdlciIsInNjb3BlIjpbIm9wZW5pZCIsInByb2ZpbGUiLCJ1c2VyX2luZm8iXSwic3ViIjoiZGUzMzRhZmUtMGZlOC1lYTExLTllZDYtODRjOWIyNzNlOGUwIiwiYXV0aF90aW1lIjoxNjA5NDExNTUyLCJpZHAiOiJpZHNydiIsInByaW1hcnlfc2lkIjoie1xyXG4gIFwiVXNlcklkXCI6IFwiZGUzMzRhZmUtMGZlOC1lYTExLTllZDYtODRjOWIyNzNlOGUwXCIsXHJcbiAgXCJDdXN0b21Qcm9wc1wiOiB7fVxyXG59IiwianRpIjoiYjliOTdmMzM5OGQ4MGU1YmYzYzM5NDcxNmM2ZTc0ZTIyN2VjODY2MTg2NDgzNWEyNzRiYjU1YTAxNzYwMDhjZSIsImFtciI6WyJjdXN0b20iXX0.o6yaKDhPbOpySNR9Sfgzomw9QEus6R0bOa2c_FomTBplolzCO1OWuCmkiAN7HQ1Gfi_K-vLZpt8Pb6ZXgizVZ15Wj8FxSuTp5HdhYdw2r_8L_jirrzDH74AEnwifmpbpEiO8Pnj2Tqwi4UmcH9-l2dqjkpUTsFXqATHTnsrB0hIOBkhV0pMSDGDGJdAL5TjiYLgPyz1edU9af2OaM-bceGcF9EpoeSYkiViH1CXJ6SyzKfPsm5W5eRgU0f43xk1sIolhcgJ8sJeOlM-BM2RulcPVUoQXl-3DLO3hsmldnzQdml9HPuInsYP46B4NRVAcM64KIS8aRXZps4LyGUiHvA";

            string fake_access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjA2NUZBRDMwNjMzQThFNTMyQjAwMTNCNzhDMjVFMDRFREQ1RUU1Q0MiLCJ4NXQiOiJCbC10TUdNNmpsTXJBQk8zakNYZ1R0MWU1Y3ciLCJ0eXAiOiJKV1QifQ.eyJuYmYiOjE2MDk0MDk1ODcsImV4cCI6MTYxMDAxNDM4NywiaXNzIjoiUmVkZW1wdGlvbi5TZXJ2ZXIuQXBpIiwiYXVkIjoiUmVkZW1wdGlvbi5TZXJ2ZXIuQXBpL3Jlc291cmNlcyIsImNsaWVudF9pZCI6Ik1hbmFnZW1lbnRBcHAtUmVzT3duZXJGbG93Iiwic2NvcGUiOlsib3BlbmlkIiwicHJvZmlsZSIsInVzZXJfaW5mbyJdLCJzdWIiOiJlYWYxNDFjMi1jNzM3LTRkZmItOGUxYi1lNmQyZjM1NmI2ZDIiLCJhdXRoX3RpbWUiOjE2MDk0MDk1ODcsImlkcCI6Imlkc3J2IiwicHJpbWFyeV9zaWQiOiJ7XHJcbiAgXCJVc2VySWRcIjogXCJlYWYxNDFjMi1jNzM3LTRkZmItOGUxYi1lNmQyZjM1NmI2ZDJcIixcclxuICBcIkN1c3RvbVByb3BzXCI6IHtcclxuICAgIFwiSWRlbnRpdHlUb2tlbklkXCI6IFwiZWM3YjE4YzQtNTA0Yi1lYjExLWE2MDctMDAxNTVkZWMyN2E3XCIsXHJcbiAgICBcImJ1c2luZXNzSWRcIjogXCI3MDc0ZDc3NS04ZWE3LTQ5ZjAtYTFkNy0wMDAwYjg3ZWRkNDhcIlxyXG4gIH1cclxufSIsImp0aSI6IjU1NTNlYTkzYTM4OTFiYWI3ZTZmMDhjNjcyYzZhZWY0MzI5MTkwOWZmYTI2MGY2ZDFkYzk0YTJiMTIzOGNjZmYiLCJhbXIiOlsiY3VzdG9tIl19.IvaJQj6G-uDWmr4Syh5a_9vkvam922OQ7kJmWKuM8IEgK5JXEKZfnzLk_0hdUGDiGWj2KGsVVpfK83-aC54dh_jf0ZlDH6s6k1L6dD3XklNFRZQOaehK7aay6wVozm9VcylwoYQaqTuIv32CcoPxc6A-A3bV6jEjJKs8JD6GL5wisLm95Cd9sNf7pZBoQDvZNuP_8hMCRwA_PY32-cljLMyupukWXVH5JvNF4a2yauqdWN475r7e6B4rcRbP3GosfoMvmf4D1c4pj8J4S1PMaUhCcrA1euxByRsvngESlmh_ndoeH3MVexqLzIKIjUAErZ4Xmi4WQtM2mskGXAo1Jg";

            // 3- Parse/Validate access_token using public key
            BitJwtToken bitJwtToken = ReadAccessToken(valid_access_token);
        }

        public static string GetPublicKey()
        {
            string password = "P@ssw0rd";

            byte[] pfxBytes = File.ReadAllBytes(@"IdentityServerCertificate.pfx");

            X509Certificate2 pfx;

            try
            {
                pfx = new X509Certificate2(pfxBytes, password, X509KeyStorageFlags.UserKeySet);
            }
            catch
            {
                pfx = new X509Certificate2(pfxBytes, password);
            }

            return pfx.GetRSAPublicKey().ToXmlString(includePrivateParameters: false);
        }

        public static BitJwtToken ReadAccessToken(string accessToken)
        {
            JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler { };

            SecurityToken jsonToken = jwtSecurityTokenHandler.ReadToken(accessToken);

            using RSA rsa = RSA.Create();

            string publicKey = @"<RSAKeyValue><Modulus>u4UfYAZweetsCgFIkQOBRXwj6G/D6X8stV5iw8hNmC0/BWPdu5voOi8QFv8nse9dfFZmvdey612PTK8q/fSHrPglrRlG+EZ9/bmafVRzddMdA10GX927Q5L8oSiUtcC7ofkPiyj+WXF/WkjszNI6qekMS6FAumoSqQRDksbmxuO//48QMUIrd6GttnR3ByDgzrOTMdEHqjEciM1w5LT2M96IaBRcDrGqY+NrsL+//wieBk6SbXrP39obHsM4/ooFLl7TArOye4Gvz9ESOT1lRnghPQDPnU0aTBFj7Q8cyqA4gk3TtDuV0vh3Gna4kYMMl8HzvLXZCAnhA/rAvqWYJQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            // Get public key from GetPublicKey() method and use it here.
            rsa.FromXmlString(publicKey);

            RsaSecurityKey rsaSecurityKey = new RsaSecurityKey(rsa);

            ClaimsPrincipal claimsPrincipal = jwtSecurityTokenHandler.ValidateToken(accessToken, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateTokenReplay = true,
                ValidateLifetime = true,
                ValidateActor = true,
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidIssuer = jsonToken.Issuer,
                ValidAudience = $"{jsonToken.Issuer}/resources",
                IssuerSigningKey = rsaSecurityKey
            }, out SecurityToken _);

            string primary_sid = claimsPrincipal.Claims
                .Single(claim => string.Equals(claim.Type, "primary_sid", StringComparison.InvariantCultureIgnoreCase))
                .Value;

            JToken json = JToken.Parse(primary_sid);

            return json.ToObject<BitJwtToken>();
        }
    }

    public class BitJwtToken
    {
        public virtual string UserId { get; set; }

        public virtual Dictionary<string, string> CustomProps { get; set; } = new Dictionary<string, string> { };
    }
}
