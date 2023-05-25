# udap-devdays-2023
[udap-dotnet](https://github.com/udap-tools/udap-dotnet) tutorial.

UDAP is the acronym for [Unified Data Access Profiles](https://www.udap.org/).
The HL7 "[Security IG](http://hl7.org/fhir/us/udap-security/)" is a constraint on UDAP.  The actual implementation guide has a long name of "Security for Scalable Registration, Authentication, and Authorization".

- FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7.
- UDAP® and the UDAP gear logo, ecosystem gears, and green lock designs are trademarks of UDAP.org. UDAP Draft Specifications are referenced and displayed in parts of this source code to document specification implementation.

## Objectives

1. 🧩 Host UDAP Metadata on a FHIR Server
2. 🧩 Host UDAP Dynamic Client Registration (DCR [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)) on an Identity Server.
3. 🧩 Secure the FHIR Server with UDAP

## Prerequisites

Clone the udap-dotnet repository.

````cli
git clone https://github.com/udap-tools/udap-dotnet.git
````

We will run the UdapEd.Server project locally to test Discovery, DCR, Token Access and finally request a resource.  Ensure you can compile and run UdapEd.Server ahead of time.  It requires .NET 7.0.

Within this [udap-devdays-2023]([JoeShook/udap-devdays-2023](https://github.com/JoeShook/udap-devdays-2023)): udap-dotnet tutorial repository ensure you can compile and run both udap.fhirserver.devdays and udap.authserver.devdays

udap.fhirserver.devdays has one patient resource loaded.  This FHIR server is a simple DemoFileSystemFhirServer implementation of Brian Postlethwaite’s [fhir-net-web-api](https://github.com/brianpos/fhir-net-web-api/tree/feature/r4b).  

udap.authserver.devdays is a Duende Identity Server implementation with a SQLite data store without DCR on UDAP. When the tutorial starts we will add DCR on UDAP to the Identity Server.

:spiral_notepad: Note: the udap.authserver.devdays prerequisite was built from the [EntityFramework Quickstart](https://docs.duendesoftware.com/identityserver/v5/quickstarts/4_ef/).

### dotnet tye

dotnet tye is not required.  The included tye.yaml is pre-configured to launch three services needed for the tutorial and includes handy links.  Try it out!

[See Project Tye](https://github.com/dotnet/tye)

```txt
dotnet tool install -g Microsoft.Tye --version "0.12.0-*" --add-source https://pkgs.dev.azure.com/dnceng/public/_packaging/dotnet6/nuget/v3/index.json
```

### Progression through the tutorial

1. Start at the prerquisite branch and ensure all services start
2. Along the way there are branches that satisfy the objectivs.
3. **prerequisite** branch is the starting point.  It is the intended branch to start and complete the tutorial.
4. **fhirserverWithUdap** branch is the tutorial solution up to  **2.🧩 udap.authserver.devdays Project**.
5. **authServerWithUdap** branch is the full working solution.

## Things to look out for

If the developer regenerates certificates with the udap.pki.devdays project during the Tutorial delete the udap.authserver.devdays.EntityFramework.db database.  And restart udap.authserver.devdays.

### On Windows

If the developer regenerates certificates with the udap.pki.devdays during the Tutorial they may then need to launch mmc.exe, the Certificates snap-in for the current user.  Go to Intermediate Certification Authorities and delete the DevDaysSubCA_1.  

## Begin Tutorial

### **1. 🧩 udap.fhirserver.devdays Project**

#### :boom: 📦 Udap.Metadata package

The following configures Udap.Metadata as an Endpoint.  There is an alternative configuration where Udap.Metadata is configured as a Controller.  See the [WeatherApi](https://github.com/JoeShook/udap-dotnet/blob/main/examples/WeatherApi/Program.cs) example.

```txt
dotnet add package Udap.Metadata.Server
```
### :boom: Include services

```csharp
builder.Services.AddUdapMetadataServer(builder.Configuration);
```

### :boom: Add Udap.Metadata to pipeline

Place it just before the MapControllers() extension method.

```csharp
app.UseUdapMetadataServer();
```

#### :boom: Add Certificates and Configuration

- Add the configuration to point the FHIR Server to the Authorization Server.

```json
"Jwt": {
    "Authority": "https://localhost:5002"
}
```

- The CertificateStore folder has already been added to the project.
- Add the following UdapMetadataOptions section to appsettings.json

````json
"UdapMetadataOptions": {
  "Enabled": true,
  "UdapMetadataConfigs": [
    {
      "Community": "udap://Community1",
      "SignedMetadataConfig": {
        "AuthorizationEndPoint": "https://localhost:5002/connect/authorize",
        "TokenEndpoint": "https://localhost:5002/connect/token",
        "RegistrationEndpoint": "https://localhost:5002/connect/register"
      }
    },
    {
      "Community": "udap://Community2",
      "SignedMetadataConfig": {
        "RegistrationSigningAlgorithms": [ "ES384" ],
        "TokenSigningAlgorithms": [ "ES384" ],
        "Issuer": "http://localhost:7016/fhir/r4",
        "Subject": "http://localhost:7016/fhir/r4",
        "AuthorizationEndPoint": "https://localhost:5002/connect/authorize",
        "TokenEndpoint": "https://localhost:5002/connect/token",
        "RegistrationEndpoint": "https://localhost:5002/connect/register"
      }
    },
    {
      "Community": "udap://Community3",
      "SignedMetadataConfig": {
        "AuthorizationEndPoint": "https://localhost:5002/connect/authorize",
        "TokenEndpoint": "https://localhost:5002/connect/token",
        "RegistrationEndpoint": "https://localhost:5002/connect/register"
      }
    }
  ]
}
````

- Add the following UdapFileCertStoreManifest section to appsettings.json

````json
"UdapFileCertStoreManifest": {
  "ResourceServers": [
    {
      "Name": "udap.fhirserver.devdays",
      "Communities": [
        {
          "Name": "udap://Community1",
          "IssuedCerts": [
            {
              "FilePath": "../../../CertificateStore/Community1/issued/DevDaysRsaClient.pfx",
              "Password": "udap-test"
            }
          ]
        },
        {
          "Name": "udap://Community2",
          "IssuedCerts": [
            {
              "FilePath": "../../../CertificateStore/Community2/issued/DevDaysECDSAClient.pfx",
              "Password": "udap-test"
            }
          ]
        },
        {
          "Name": "udap://Community3",
          "IssuedCerts": [
            {
              "FilePath": "../../../CertificateStore/Community3/issued/DevDaysRevokedClient.pfx",
              "Password": "udap-test"
            }
          ]
        }
      ]
    }
  ]
}
````

#### :boom: Run udap.fhirserver.devdays Project

- [https://localhost:7016/fhir/r4?_format=json](https://localhost:7016/fhir/r4?_format=json)
- [https://localhost:7016/fhir/r4/Patient](https://localhost:7016/fhir/r4/Patient)

Default UDAP metadata endpoint.

- [https://localhost:7016/fhir/r4/.well-known/udap](https://localhost:7016/fhir/r4/.well-known/udap)

Convenience links to find community specific UDAP metadata endpoints

- [https://localhost:7016/fhir/r4/.well-known/udap/communities](https://localhost:7016/fhir/r4/.well-known/udap/communities)
- [https://localhost:7016/fhir/r4/.well-known/udap/communities/ashtml](https://localhost:7016/fhir/r4/.well-known/udap/communities/ashtml)

## :boom: Launch [UdapEd.Server](https://localhost:7041)

Validate the https://localhost:7016/fhir/r4/.well-known/udap signed metadata with [UdapEd UI Client](https://localhost:7041).  Upload the [Community1 anchor](./udap.pki.devdays/CertificateStore/Community1/DevDaysCA_1.crt) as the clients known trust anchor.

[Client Validation Demo](https://storage.googleapis.com/dotnet_udap_content/DevDays2023Metadata.mp4)

[![Client Validation Demo](https://storage.googleapis.com/dotnet_udap_content/DevDays2023Metadata.jpg)](https://storage.googleapis.com/dotnet_udap_content/DevDays2023Metadata.mp4)

### 3.A🧩 Secure the FHIR Server with UDAP

### :boom: Add Authentication

```txt
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer -v 6.*
```

Register services required by authentication services. Specifically the Bearer schema.

````csharp
builder.Services.AddAuthentication(
  OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)

  .AddJwtBearer(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, 
    options =>
    {
      options.Authority = builder.Configuration["Jwt:Authority"];
      options.RequireHttpsMetadata = 
          bool.Parse(
              builder.Configuration["Jwt:RequireHttpsMetadata"] ?? "true"
              );        
      
      options.TokenValidationParameters = new TokenValidationParameters
      {
          ValidateAudience = false
      };
    }
  );
````

Add the AuthorizationMiddleware with the UseAuthentication() and UseAuthorization() extensions.
Add the the authorization policy to the endpoints with the RequireAuthorization() extension.
The order of the middleware is demonstrated in the following code.

```csharp
  app.UsePathBase(new PathString("/fhir/r4"));
  app.UseRouting();

  app.UseAuthentication();
  app.UseAuthorization();
  
  app.UseHttpsRedirection();
  app.UseUdapMetadataServer();
  app.MapControllers().RequireAuthorization();
```

Requesting a Patient should now result in a HTTP Status code of 401.

- [https://localhost:7016/fhir/r4/Patient](https://localhost:7016/fhir/r4/Patient)

To finish objective #2 the udap.authserver.devdays Project will need to be configured as the UDAP authorization server.  Re-test this in section 3.B 🧩 later.

### **2.🧩 udap.authserver.devdays Project**

Let's enable DCR on UDAP

#### 1. :boom: Apply the AddUdapServer extension method to the AddIdentityServer extension.  This will enable DCR on UDAP

```txt
dotnet add package Udap.Server
```

````csharp
builder.Services.AddIdentityServer()
 .AddUdapServer(
    options =>
        {
            var udapServerOptions = builder.Configuration.
              GetOption<ServerSettings>("ServerSettings");
            options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
            options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
            options.ServerSupport = udapServerOptions.ServerSupport;
            options.ForceStateParamOnAuthorizationCode = udapServerOptions.
                ForceStateParamOnAuthorizationCode;
        },
    options =>
        options.UdapDbContext = b =>
                b.UseSqlite(connectionString,
                    dbOpts => 
                        dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName))
        ),
        baseUrl: "http://localhost:5002/connect/register"
````

Add ```UdapServer()``` to the pipeline.  Place it before ```app.UseIdentityServer()```.

```txt
app.UseUdapServer();
app.UseIdentityServer()
```

#### 2. :boom: Add the Udap.Server database schema to the Identity Server Schema

Uncomment ```await InitializeDatabaseWithUdap(serviceScope, configDbContext);``` in ```SeedData.cs```

Run Entity Framework Migrations

Install ```dotnet-ef``` if it does not exist

```txt
dotnet tool install --global dotnet-ef
```

```text
dotnet ef migrations add InitialIdentityServerUdapDbMigration -c UdapDbContext -o Data/Migrations/IdentityServer/UdapDb
```

---
:spiral_notepad: Note: You can launch all apps with ```tye run``` from solution folder.

See it in action in the following demo.  Details steps below the demo.

[Client Validation Demo](https://storage.googleapis.com/dotnet_udap_content/tye_UDAP_Authorization.mp4)

[![Client Validation Demo](https://storage.googleapis.com/dotnet_udap_content/tye_UDAP_Authorization.jpg)](https://storage.googleapis.com/dotnet_udap_content/tye_UDAP_Authorization.mp4)

#### 3. :boom: Launch udap.authserver.devdays

#### 4. :boom: Ensure udap.fhirserver.devdays is running

#### 5. :boom: Launch UdapEd.Server

Start in :arrow_right: **Discovery** area.  Enter the FHIR Server's Base URL; https://localhost:7016/fhir/r4 and click the query button :white_square_button:.

Without an anchor loaded to validate trust the following alert should be presented:
- :exclamation: <span style="color:red">No anchor loaded. Un-Validated resource server.</span>

Load the trust anchor for the default community ( udap://Community1 ).  Find the anchor in the Anchors/Community1 folder of this repository.

Click the query button :white_square_button: again and you should see the alert is resolved.  
Read more on the home page of the UdapEd tool on how to experiment with more interesting failure cases and multi community use cases.

Continue in the :arrow_right: **Registration** area.  Experiment with and without a client certificate loaded.  Click the Client Cert button :white_square_button: to load a client certificate.  This time you will need to supply a password to load a P12 file.  All of the certificates generated for testing the udap-dotnet RI use "udap-test" as a password to keep it simple.  Find the udap://Community1 **client certificate with key** in the Issued/Community1 folder of this repository.

:spiral_notepad: Note: In the Raw Software Statement area the user can change the software statement before continuing to signing the message via the Build Request Body button :white_square_button:.  Uses could be to simply edit requested scopes or invalidated the request by changing the subject (iss).  

Continue in the :arrow_right: B2B area.  Depending on which Grant Type was registered for click the Build... button :white_square_button:.  

:spiral_notepad: Note: When using Authorization Code Grant type the user can alter the GET request to /authorize.  This will again allow scope changes or other changes to experiment with force failures.

Continue in the :arrow_right: Search area or take the **Access Token** and use it in something like Postman.

## 3.B 🧩 Secure the FHIR Server with UDAP

At this point using the **Access Token** successfully will satisfy the objective.  

🗒️ Note: Match is not supported on this sample FHIR server.  

## Advanced

### **🧩 Add UDAP Metadata to the Firely Server**

Demo if we have time.

## Comments

The 📦Udap.Server package is an implementation of DCR on UDAP.  At the time of writing this package, Identity Server did not have [DCR](https://docs.duendesoftware.com/identityserver/v6/configuration/dcr/) (Dynamic Client Registration).  It has been added in the recent past.   The plan is to revisit this area and see how much of 📦Udap.Server package code can be removed in favor of the Identity Server core DCR API.

## Questions
