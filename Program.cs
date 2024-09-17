using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Web;
using Newtonsoft.Json.Linq;
using System.Linq;

class Program
{
    private static string selectedSiteId;

    static async Task Main(string[] args)
    {
        var clientId = "956ebbbe-785a-4948-8592-ad2b826b0e6a";
        var redirectUri = "https://app-accept.saltoks.com/callback";
        var scope = "user_api.full_access openid profile offline_access";
        var authorizationEndpoint = "https://clp-accept-identityserver.saltoks.com/connect/authorize";

        var codeVerifier = PKCEHelper.GenerateCodeVerifier();
        var codeChallenge = PKCEHelper.GenerateCodeChallenge(codeVerifier);
        var codeChallengeMethod = "S256";

        var authorizationUrl = $"{authorizationEndpoint}?response_type=code" +
                               $"&client_id={clientId}" +
                               $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                               $"&scope={Uri.EscapeDataString(scope)}" +
                               $"&code_challenge={codeChallenge}" +
                               $"&code_challenge_method={codeChallengeMethod}";

        Console.WriteLine("Opening the browser for authorization...");
        Process.Start(new ProcessStartInfo
        {
            FileName = authorizationUrl,
            UseShellExecute = true
        });

        Console.WriteLine("Paste the full callback URL here:");
        var callbackUrl = Console.ReadLine();

        var authorizationCode = ExtractAuthorizationCode(callbackUrl);

        if (string.IsNullOrEmpty(authorizationCode))
        {
            Console.WriteLine("Failed to extract the authorization code from the URL.");
            return;
        }

        var accessToken = await ExchangeAuthorizationCodeForAccessToken(authorizationCode, codeVerifier, clientId, redirectUri);

        if (string.IsNullOrEmpty(accessToken))
        {
            Console.WriteLine("Failed to retrieve access token.");
            return;
        }

        await DisplaySiteSelectionMenu(accessToken);
    }

    private static string ExtractAuthorizationCode(string callbackUrl)
    {
        var uri = new Uri(callbackUrl);
        var query = HttpUtility.ParseQueryString(uri.Query);
        return query["code"];
    }

    private static async Task<string> ExchangeAuthorizationCodeForAccessToken(string code, string codeVerifier, string clientId, string redirectUri)
    {
        var tokenUrl = "https://clp-accept-identityserver.saltoks.com/connect/token";

        using (var httpClient = new HttpClient())
        {
            var request = new HttpRequestMessage(HttpMethod.Post, tokenUrl);
            var parameters = new Dictionary<string, string>
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "redirect_uri", redirectUri },
                { "client_id", clientId },
                { "code_verifier", codeVerifier }
            };

            request.Content = new FormUrlEncodedContent(parameters);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes($"{clientId}:<client_secret>")));

            var response = await httpClient.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var json = JObject.Parse(content);
                var accessToken = json["access_token"].ToString();
                return accessToken;
            }
            else
            {
                Console.WriteLine("Error: " + content);
                return null;
            }
        }
    }

    private static async Task DisplaySiteSelectionMenu(string accessToken)
    {
        var apiUrl = "https://clp-accept-user.my-clay.com/v1.1/sites/";

        using (var httpClient = new HttpClient())
        {
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await httpClient.GetAsync(apiUrl);
            var content = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var json = JObject.Parse(content);
                var sites = json["items"]?.ToObject<JArray>();

                if (sites == null || !sites.Any())
                {
                    Console.WriteLine("No sites found.");
                    return;
                }

                Console.WriteLine("Select a site:");
                for (int i = 0; i < sites.Count; i++)
                {
                    var site = sites[i];
                    var id = site["id"].ToString();
                    var customerReference = site["customer_reference"].ToString();
                    Console.WriteLine($"{i + 1}: {customerReference} (ID: {id})");
                }

                Console.WriteLine("Enter the number of the site you want to use:");
                var choice = Console.ReadLine();

                if (int.TryParse(choice, out int index) && index > 0 && index <= sites.Count)
                {
                    selectedSiteId = sites[index - 1]["id"].ToString();
                    Console.WriteLine($"Selected Site ID: {selectedSiteId}");

                    await DisplayActionMenu(accessToken);
                }
                else
                {
                    Console.WriteLine("Invalid choice.");
                }
            }
            else
            {
                Console.WriteLine("Error: " + content);
            }
        }
    }

    private static async Task DisplayActionMenu(string accessToken)
    {
        while (true)
        {
            Console.WriteLine("\nSelect an action:");
            Console.WriteLine("1: Choose a new site");
            Console.WriteLine("2: View all locks and unlock one");
            Console.WriteLine("3: View all users");
            Console.WriteLine("4: Exit");

            var choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    await DisplaySiteSelectionMenu(accessToken);
                    break;

                case "2":
                    await GetAndUnlockLock(accessToken, selectedSiteId);
                    break;

                case "3":
                    await GetUsers(accessToken, selectedSiteId);
                    break;

                case "4":
                    Console.WriteLine("Exiting...");
                    return;

                default:
                    Console.WriteLine("Invalid choice. Please enter a number between 1 and 4.");
                    break;
            }
        }
    }

    private static async Task GetAndUnlockLock(string accessToken, string siteId)
{
    var apiUrl = $"https://clp-accept-user.my-clay.com/v1.1/sites/{siteId}/locks";

    using (var httpClient = new HttpClient())
    {
        httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

        var response = await httpClient.GetAsync(apiUrl);
        var content = await response.Content.ReadAsStringAsync();

        if (response.IsSuccessStatusCode)
        {
            var json = JObject.Parse(content);
            var locks = json["items"]?.ToObject<JArray>();

            // Check if locks array is null or empty
            if (locks == null || !locks.Any())
            {
                Console.WriteLine("No locks found.");
                return;
            }

            Console.WriteLine("Select a lock to unlock:");
            for (int i = 0; i < locks.Count; i++)
            {
                var lockObj = locks[i];
                var id = lockObj["id"]?.ToString();
                var name = lockObj["name"]?.ToString();

                // Handle case where 'id' or 'name' might be missing
                if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(name))
                {
                    Console.WriteLine($"Lock {i + 1}: (Invalid data, ID or Name is missing)");
                }
                else
                {
                    Console.WriteLine($"{i + 1}: {name} (ID: {id})");
                }
            }

            Console.WriteLine("Enter the number of the lock you want to unlock:");
            var choice = Console.ReadLine();

            if (int.TryParse(choice, out int index) && index > 0 && index <= locks.Count)
            {
                var lockId = locks[index - 1]["id"]?.ToString();
                if (string.IsNullOrEmpty(lockId))
                {
                    Console.WriteLine("Error: Selected lock has an invalid ID.");
                    return;
                }

                Console.WriteLine($"Selected Lock ID: {lockId}");

                // Ask for OTP
                Console.WriteLine("Enter OTP to unlock the lock:");
                var otp = Console.ReadLine();

                if (!string.IsNullOrEmpty(otp))
                {
                    await UnlockLock(accessToken, siteId, lockId, otp);
                }
                else
                {
                    Console.WriteLine("Invalid OTP.");
                }
            }
            else
            {
                Console.WriteLine("Invalid choice.");
            }
        }
        else
        {
            Console.WriteLine("Error fetching locks: " + content);
        }
    }
}


    private static async Task UnlockLock(string accessToken, string siteId, string lockId, string otp)
    {
        var apiUrl = $"https://clp-accept-user.my-clay.com/v1.1/sites/{siteId}/locks/{lockId}/locking";
        var body = new JObject
        {
            { "locked_state", "unlocked" },
            { "otp", otp }
        };

        using (var httpClient = new HttpClient())
        {
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            var content = new StringContent(body.ToString(), System.Text.Encoding.UTF8, "application/json");

            var response = await httpClient.PatchAsync(apiUrl, content);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Lock successfully unlocked!");
            }
            else
            {
                Console.WriteLine("Error unlocking the lock: " + responseBody);
            }
        }
    }

    private static async Task GetUsers(string accessToken, string siteId)
    {
        var apiUrl = $"https://clp-accept-user.my-clay.com/v1.1/sites/{siteId}/users";

        using (var httpClient = new HttpClient())
        {
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await httpClient.GetAsync(apiUrl);
            var content = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("Users:");
                Console.WriteLine(content);
            }
            else
            {
                Console.WriteLine("Error: " + content);
            }
        }
    }
}
