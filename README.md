# JWTAth
.NET 6 Web API - Create JSON Web Tokens (JWT) - User Registration / Login / Role-Based Authorization
Read Claim and create refresh token on Server side

Step: Register => Login => Refresh token save in Client Cookie, Access Token (JWT) can save Local Storage or Cookie 
=> request API Weather Forecast with access token in header 
=> if Access token expires => need call refresh-token api to get new tokens
