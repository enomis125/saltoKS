using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Web;
using Newtonsoft.Json.Linq;
using System.Linq;
using System.Data.SqlClient;
using System.IO; 

class Program
{
    private static string selectedSiteId;

    static async Task Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        // Lê a connection string do arquivo
        string connectionString = ReadConnectionStringFromFile("connectionString.txt");

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

        Console.WriteLine("A abrir o navegador para autorização...");
        Process.Start(new ProcessStartInfo
        {
            FileName = authorizationUrl,
            UseShellExecute = true
        });

        Console.WriteLine("Cole o URL completo de callback aqui:");
        var callbackUrl = Console.ReadLine();

        var authorizationCode = ExtractAuthorizationCode(callbackUrl);

        if (string.IsNullOrEmpty(authorizationCode))
        {
            Console.WriteLine("Falha ao extrair o código de autorização do URL.");
            return;
        }

        var accessToken = await ExchangeAuthorizationCodeForAccessToken(authorizationCode, codeVerifier, clientId, redirectUri);

        if (string.IsNullOrEmpty(accessToken))
        {
            Console.WriteLine("Falha ao obter o token de acesso.");
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
                Console.WriteLine("Erro: " + content);
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
                    Console.WriteLine("Nenhum site encontrado.");
                    return;
                }

                Console.WriteLine("Selecione um site:");
                for (int i = 0; i < sites.Count; i++)
                {
                    var site = sites[i];
                    var id = site["id"].ToString();
                    var customerReference = site["customer_reference"].ToString();
                    Console.WriteLine($"{i + 1}: {customerReference} (ID: {id})");
                }

                Console.WriteLine("Introduza o número do site que deseja usar:");
                var choice = Console.ReadLine();

                if (int.TryParse(choice, out int index) && index > 0 && index <= sites.Count)
                {
                    selectedSiteId = sites[index - 1]["id"].ToString();
                    Console.WriteLine($"ID do Site Selecionado: {selectedSiteId}");

                    await DisplayActionMenu(accessToken);
                }
                else
                {
                    Console.WriteLine("Escolha inválida.");
                }
            }
            else
            {
                Console.WriteLine("Erro: " + content);
            }
        }
    }

    private static async Task DisplayActionMenu(string accessToken)
    {
        while (true)
        {
            Console.WriteLine("\nSelecione uma ação:");
            Console.WriteLine("1: Escolher um novo site");
            Console.WriteLine("2: Ver todos os fechos e desbloquear um");
            Console.WriteLine("3: Ver todos os utilizadores");
            Console.WriteLine("4: Atribuir PIN a um utilizador");
            Console.WriteLine("5: Sair");

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
                    await AssignPinToUser(accessToken, selectedSiteId);
                    break;

                case "5":
                    Console.WriteLine("A sair...");
                    return;

                default:
                    Console.WriteLine("Escolha inválida. Por favor, introduza um número entre 1 e 5.");
                    break;
            }
        }
    }

//lê a connection string do txt
    private static string ReadConnectionStringFromFile(string filePath)
    {
        try
        {
            // Lê todo o conteúdo do arquivo e retorna como string
            return File.ReadAllText(filePath);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro ao ler a connection string do arquivo: {ex.Message}");
            return null;
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

                if (locks == null || !locks.Any())
                {
                    Console.WriteLine("Nenhum fecho encontrado.");
                    return;
                }

                Console.WriteLine("Selecione um fecho para desbloquear:");
                for (int i = 0; i < locks.Count; i++)
                {
                    var lockObj = locks[i];
                    var id = lockObj["id"]?.ToString();
                    var name = lockObj["name"]?.ToString();

                    if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(name))
                    {
                        Console.WriteLine($"Fecho {i + 1}: (Dados inválidos, ID ou Nome está faltando)");
                    }
                    else
                    {
                        Console.WriteLine($"{i + 1}: {name} (ID: {id})");
                    }
                }

                Console.WriteLine("Introduza o número do fecho que deseja desbloquear:");
                var choice = Console.ReadLine();

                if (int.TryParse(choice, out int index) && index > 0 && index <= locks.Count)
                {
                    var lockId = locks[index - 1]["id"]?.ToString();
                    if (string.IsNullOrEmpty(lockId))
                    {
                        Console.WriteLine("Erro: O fecho selecionado tem um ID inválido.");
                        return;
                    }

                    Console.WriteLine($"ID do Fecho Selecionado: {lockId}");

                    Console.WriteLine("Introduza o OTP para desbloquear o fecho:");
                    var otp = Console.ReadLine();

                    if (!string.IsNullOrEmpty(otp))
                    {
                        await UnlockLock(accessToken, siteId, lockId, otp);
                    }
                    else
                    {
                        Console.WriteLine("OTP inválido.");
                    }
                }
                else
                {
                    Console.WriteLine("Escolha inválida.");
                }
            }
            else
            {
                Console.WriteLine("Erro ao obter fechos: " + content);
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
                Console.WriteLine("Fecho desbloqueado com sucesso!");
            }
            else
            {
                Console.WriteLine("Erro ao desbloquear o fecho: " + responseBody);
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
                var json = JObject.Parse(content);
                var users = json["items"]?.ToObject<JArray>();

                if (users == null || !users.Any())
                {
                    Console.WriteLine("Nenhum utilizador encontrado.");
                    return;
                }

                Console.WriteLine("Utilizadores:");

                foreach (var userObj in users)
                {
                    var user = userObj["user"];
                    var roles = userObj["roles"];

                    // Exibir detalhes do utilizador
                    Console.WriteLine($"Nome: {user["first_name"]} {user["last_name"]}");
                    Console.WriteLine($"Email: {user["email"]}");

                    // Exibir funções do utilizador
                    Console.Write("Funções: ");
                    foreach (var role in roles)
                    {
                        Console.Write($"{role["customer_reference"]} ");
                    }

                    Console.WriteLine("\n-------------------------");
                }
            }
            else
            {
                Console.WriteLine("Erro: " + content);
            }
        }
    }

    private static async Task AssignPinToUser(string accessToken, string siteId)
    {
        var apiUrl = $"https://clp-accept-user.my-clay.com/v1.1/sites/{siteId}/users";

        using (var httpClient = new HttpClient())
        {
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await httpClient.GetAsync(apiUrl);
            var content = await response.Content.ReadAsStringAsync();

            if (response.IsSuccessStatusCode)
            {
                var json = JObject.Parse(content);
                var users = json["items"]?.ToObject<JArray>();

                if (users == null || !users.Any())
                {
                    Console.WriteLine("Nenhum utilizador encontrado.");
                    return;
                }

                // Exibir lista de utilizadores
                Console.WriteLine("Selecione um utilizador para atribuir um PIN:");
                for (int i = 0; i < users.Count; i++)
                {
                    var user = users[i]["user"];
                    var id = users[i]["id"].ToString();
                    var firstName = user["first_name"].ToString();
                    var lastName = user["last_name"].ToString();
                    Console.WriteLine($"{i + 1}: {firstName} {lastName} (ID: {id})");
                }

                Console.WriteLine("Introduza o número do utilizador:");
                var choice = Console.ReadLine();

                if (int.TryParse(choice, out int index) && index > 0 && index <= users.Count)
                {
                    var userId = users[index - 1]["id"].ToString();
                    Console.WriteLine($"ID do Utilizador Selecionado: {userId}");

                    Console.WriteLine("Introduza a data de expiração no formato AAAA-MM-DDTHH:MM:SS (exemplo: 2024-09-30T14:12:14):");
                    var expiryDateInput = Console.ReadLine();

                    if (DateTime.TryParse(expiryDateInput, out DateTime expiryDate))
                    {
                        await AssignPin(accessToken, siteId, userId, expiryDate);
                    }
                    else
                    {
                        Console.WriteLine("Data de expiração inválida.");
                        await AssignPin(accessToken, siteId, userId, expiryDate);
                    }
                }
                else
                {
                    Console.WriteLine("Escolha inválida.");
                }
            }
            else
            {
                Console.WriteLine("Erro: " + content);
            }
        }
    }

    private static async Task AssignPin(string accessToken, string siteId, string userId, DateTime expiryDate)
{
    var apiUrl = $"https://clp-accept-user.my-clay.com/v1.1/sites/{siteId}/users/{userId}/pin";
    
    var body = new JObject
    {
        { "expiry_date", expiryDate.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
    };

    using (var httpClient = new HttpClient())
    {
        httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        var content = new StringContent(body.ToString(), System.Text.Encoding.UTF8, "application/json");

        var response = await httpClient.PutAsync(apiUrl, content);
        var responseBody = await response.Content.ReadAsStringAsync();

        var requestType = "PUT";
        var responseStatus = (int)response.StatusCode;

        Console.WriteLine("Código de Status: " + responseStatus);
        Console.WriteLine("Descrição do Status: " + response.ReasonPhrase);
        Console.WriteLine("Conteúdo da resposta:");
        Console.WriteLine(responseBody);

        if (response.IsSuccessStatusCode)
        {
            var pinCode = responseBody.Trim().Trim('"') + "#";
            Console.WriteLine("PIN atribuído com sucesso!");
            Console.WriteLine("PIN: " + pinCode);

            SavePinToDatabase(userId, pinCode, body.ToString(), siteId, responseBody, apiUrl, responseStatus, requestType, false);
        }
        else
        {
            Console.WriteLine("Erro ao atribuir PIN: " + responseBody);
            SavePinToDatabase(userId, string.Empty, body.ToString(), siteId, responseBody, apiUrl, responseStatus, requestType, true);
        }
    }
}


    private static void SavePinToDatabase(string userId, string pinCode, string requestBody, string siteId, string responseBody, string requestUrl, int responseStatus, string requestType, bool isError)
{
    string connectionString = ReadConnectionStringFromFile("connectionString.txt"); // Lê novamente se necessário

    try
    {
        using (var connection = new SqlConnection(connectionString))
        {
            connection.Open();

            var command = new SqlCommand(@"
                INSERT INTO requestRecordsCode (
                    requestDate,
                    siteID,
                    saltoUserID,
                    code,
                    requestBody,
                    responseBody,
                    requestURL,
                    responseStatus,
                    requestType
                ) VALUES (
                    @RequestDate,
                    @SiteID,
                    @SaltoUserID,
                    @Code,
                    @RequestBody,
                    @ResponseBody,
                    @RequestURL,
                    @ResponseStatus,
                    @RequestType
                );
            ", connection);

            command.Parameters.AddWithValue("@RequestDate", DateTime.Now);
            command.Parameters.AddWithValue("@SiteID", siteId);
            command.Parameters.AddWithValue("@SaltoUserID", userId);
            command.Parameters.AddWithValue("@Code", pinCode);
            command.Parameters.AddWithValue("@RequestBody", requestBody);
            command.Parameters.AddWithValue("@ResponseBody", responseBody);
            command.Parameters.AddWithValue("@RequestURL", requestUrl);
            command.Parameters.AddWithValue("@ResponseStatus", responseStatus);
            command.Parameters.AddWithValue("@RequestType", requestType);

            command.ExecuteNonQuery();
        }

        Console.WriteLine("PIN salvo na base de dados local.");
    }
    catch (Exception ex)
    {
        Console.WriteLine("Erro ao salvar PIN na base de dados: " + ex.Message);
        // Log the error to the database
        LogErrorToDatabase(siteId, userId, requestBody, responseBody, requestUrl, responseStatus, requestType);
    }
}

private static void LogErrorToDatabase(string siteId, string userId, string requestBody, string responseBody, string requestUrl, int responseStatus, string requestType)
{
    string connectionString = "Server=ENOMIS\\MSSQLSERVER01;Database=protelmprado;Integrated Security=True;";

    try
    {
        using (var connection = new SqlConnection(connectionString))
        {
            connection.Open();

            var command = new SqlCommand(@"
                INSERT INTO requestRecordsCode (
                    requestDate,
                    siteID,
                    saltoUserID,
                    requestBody,
                    responseBody,
                    requestURL,
                    responseStatus,
                    requestType
                ) VALUES (
                    @RequestDate,
                    @SiteID,
                    @SaltoUserID,
                    @RequestBody,
                    @ResponseBody,
                    @RequestURL,
                    @ResponseStatus,
                    @RequestType
                );
            ", connection);

            command.Parameters.AddWithValue("@RequestDate", DateTime.Now);
            command.Parameters.AddWithValue("@SiteID", siteId);
            command.Parameters.AddWithValue("@SaltoUserID", userId);
            command.Parameters.AddWithValue("@RequestBody", requestBody);
            command.Parameters.AddWithValue("@ResponseBody", responseBody);
            command.Parameters.AddWithValue("@RequestURL", requestUrl);
            command.Parameters.AddWithValue("@ResponseStatus", responseStatus);
            command.Parameters.AddWithValue("@RequestType", requestType);

            command.ExecuteNonQuery();
        }

        Console.WriteLine("Erro registrado na base de dados local.");
    }
    catch (Exception ex)
    {
        Console.WriteLine("Erro ao salvar o registro de erro na base de dados: " + ex.Message);
    }
}

}