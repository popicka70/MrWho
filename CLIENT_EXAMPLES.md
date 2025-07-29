# OIDC Client Configuration Examples

## Postman / HTTP Client Examples

### 1. Get Access Token (Password Grant)

```http
POST {{baseUrl}}/connect/token
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=mrwho-client&client_secret=mrwho-secret&username=admin@mrwho.com&password=Admin123!&scope=email profile
```

### 2. Test Public Endpoint

```http
GET {{baseUrl}}/api/test/public
```

### 3. Test Protected Endpoint

```http
GET {{baseUrl}}/api/test/protected
Authorization: Bearer {{access_token}}
```

### 4. Get User Info

```http
GET {{baseUrl}}/api/test/user-info
Authorization: Bearer {{access_token}}
```

## .NET Client Example

```csharp
using System.Text;
using System.Text.Json;

public class OidcClient
{
    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;
    private readonly string _clientId;
    private readonly string _clientSecret;

    public OidcClient(HttpClient httpClient, string baseUrl, string clientId, string clientSecret)
    {
        _httpClient = httpClient;
        _baseUrl = baseUrl;
        _clientId = clientId;
        _clientSecret = clientSecret;
    }

    public async Task<TokenResponse> GetTokenAsync(string username, string password, string scope = "email profile")
    {
        var parameters = new Dictionary<string, string>
        {
            {"grant_type", "password"},
            {"client_id", _clientId},
            {"client_secret", _clientSecret},
            {"username", username},
            {"password", password},
            {"scope", scope}
        };

        var content = new FormUrlEncodedContent(parameters);
        var response = await _httpClient.PostAsync($"{_baseUrl}/connect/token", content);
        
        response.EnsureSuccessStatusCode();
        
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<TokenResponse>(json, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        });
    }

    public async Task<UserInfo> GetUserInfoAsync(string accessToken)
    {
        _httpClient.DefaultRequestHeaders.Authorization = 
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            
        var response = await _httpClient.GetAsync($"{_baseUrl}/api/test/user-info");
        response.EnsureSuccessStatusCode();
        
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<UserInfo>(json, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }
}

public class TokenResponse
{
    public string AccessToken { get; set; }
    public string TokenType { get; set; }
    public int ExpiresIn { get; set; }
    public string Scope { get; set; }
}

public class UserInfo
{
    public string Subject { get; set; }
    public string Email { get; set; }
    public string EmailVerified { get; set; }
    public string PreferredUsername { get; set; }
    public string GivenName { get; set; }
    public string FamilyName { get; set; }
    public string Name { get; set; }
    public string Role { get; set; }
}
```

## JavaScript/TypeScript Client Example

```typescript
interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

interface UserInfo {
  subject: string;
  email: string;
  emailVerified: string;
  preferredUsername: string;
  givenName: string;
  familyName: string;
  name: string;
  role: string;
}

class OidcClient {
  constructor(
    private baseUrl: string,
    private clientId: string,
    private clientSecret: string
  ) {}

  async getToken(username: string, password: string, scope: string = 'email profile'): Promise<TokenResponse> {
    const params = new URLSearchParams({
      grant_type: 'password',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      username,
      password,
      scope
    });

    const response = await fetch(`${this.baseUrl}/connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params
    });

    if (!response.ok) {
      throw new Error(`Token request failed: ${response.statusText}`);
    }

    return response.json();
  }

  async getUserInfo(accessToken: string): Promise<UserInfo> {
    const response = await fetch(`${this.baseUrl}/api/test/user-info`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    if (!response.ok) {
      throw new Error(`User info request failed: ${response.statusText}`);
    }

    return response.json();
  }

  async callProtectedApi(accessToken: string, endpoint: string): Promise<any> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.statusText}`);
    }

    return response.json();
  }
}

// Usage example
const client = new OidcClient('https://localhost:7001', 'mrwho-client', 'mrwho-secret');

async function example() {
  try {
    // Get token
    const token = await client.getToken('admin@mrwho.com', 'Admin123!');
    console.log('Access token:', token.access_token);

    // Get user info
    const userInfo = await client.getUserInfo(token.access_token);
    console.log('User info:', userInfo);

    // Call protected API
    const protectedData = await client.callProtectedApi(token.access_token, '/api/test/protected');
    console.log('Protected data:', protectedData);
  } catch (error) {
    console.error('Error:', error);
  }
}
```

## Configuration for Popular OIDC Libraries

### IdentityServer4/.NET Client

```csharp
services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "https://localhost:7001";
        options.RequireHttpsMetadata = false; // Only for development
        options.Audience = "api1";
    });
```

### Angular with angular-oauth2-oidc

```typescript
import { AuthConfig } from 'angular-oauth2-oidc';

export const authConfig: AuthConfig = {
  issuer: 'https://localhost:7001',
  redirectUri: window.location.origin,
  clientId: 'mrwho-client',
  responseType: 'code',
  scope: 'openid profile email',
  showDebugInformation: true,
};
```

### React with oidc-client

```javascript
import { UserManager } from 'oidc-client';

const userManager = new UserManager({
  authority: 'https://localhost:7001',
  client_id: 'mrwho-client',
  redirect_uri: 'http://localhost:3000/callback',
  response_type: 'code',
  scope: 'openid profile email',
  post_logout_redirect_uri: 'http://localhost:3000'
});
```