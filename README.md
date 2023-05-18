# udap-devdays-2023
[udap-dotnet](https://github.com/udap-tools/udap-dotnet) tutorial.

UDAP is the acronym for [Unified Data Access Profiles](https://www.udap.org/).
The HL7 "[Security IG](http://hl7.org/fhir/us/udap-security/)" is a constraint on UDAP.  The actual implementation guide has a long name of "Security for Scalable Registration, Authentication, and Authorization".

- FHIR® is the registered trademark of HL7 and is used with the permission of HL7. Use of the FHIR trademark does not constitute endorsement of the contents of this repository by HL7.
- UDAP® and the UDAP gear logo, ecosystem gears, and green lock designs are trademarks of UDAP.org. UDAP Draft Specifications are referenced and displayed in parts of this source code to document specification implementation.

## Objectives

1. Host UDAP Metadata on a FHIR Server
2. Host UDAP Dynamic Client Registration (DCR [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)) on an Identity Server.
3. Secure the FHIR Server with UDAP

## Prerequisites

Clone the udap-dotnet repository.

````cli
git clone https://github.com/udap-tools/udap-dotnet.git
````

We will run the UdapEd.Server project locally to test Discovery, DCR, Token Access and finally request a resource.
Ensure you can compile and run UdapEd.Server ahead of time.

Within this [udap-devdays-2023]( JoeShook/udap-devdays-2023: udap-dotnet tutorial. (github.com)) repository ensure you can compile and run both udap.fhirserver.devdays and udap.authserver.devdays

udap.fhirserver.devdays has one patient resource loaded.  This FHIR server is a simple DemoFileSystemFhirServer implementation of 
Brian Postlethwaite’s fhir-net-web-api, which has its roots in the original Spark FHIR Server prior to DSTU2 release.  

udap.authserver.devdays is an Identity Server with a SQLite data store without DCR on UDAP.

## 📖 Start Tutorial

### **🧩 udap.fhirserver.devdays Project**

#### 1. :boom: Add UDAP Metadata

````csharp
builder.Services.AddUdapMetadataServer(builder.Configuration);
````

#### 2. :boom: Add Certificates and Configuration

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
          "Issuer": "http://localhost/fhir/r4",
          "Subject": "http://localhost/fhir/r4",
          "AuthorizationEndPoint": "https://localhost:5002/connect/authorize",
          "TokenEndpoint": "https://localhost:5002/connect/token",
          "RegistrationEndpoint": "https://localhost:5002/connect/register"
        }    
      },
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
                "FilePath": "CertificateStore/issued/fhirLabsApiClientLocalhostCert.pfx",
                "Password": "udap-test"
              }
            ]
          },
          {
            "Name": "udap://ECDSA/",
            "IssuedCerts": [
              {
                "FilePath": "CertStore/issued/fhirLabsApiClientLocalhostCert6_ECDSA.pfx",
                "Password": "udap-test"
              }
            ]
          }
        ]
      }
    ]
}
````

#### 3. :boom: Run udap.fhirserver.devdays Project

- [https://localhost:7016/fhir/r4?_format=json](https://localhost:7016/fhir/r4?_format=json)
- [https://localhost:7016/fhir/r4/Patient](https://localhost:7016/fhir/r4/Patient)

Default UDAP metadata endpoint.

- [https://localhost:7016/fhir/r4/.well-known/udap](https://localhost:7016/fhir/r4/.well-known/udap)

Convenience links to find community specific UDAP metadata endpoints

- [https://localhost:7016/fhir/r4/.well-known/udap/communities](https://localhost:7016/fhir/r4/.well-known/udap/communities)
- [https://localhost:7016/fhir/r4/.well-known/udap](https://localhost:7016/fhir/r4/.well-known/udap)

#### 4. :boom: Add Authentication

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

Requesting a Patient should now result in a HTTP Status code of 401.

- [https://localhost:7016/fhir/r4/Patient](https://localhost:7016/fhir/r4/Patient)

### **🧩 udap.authserver.devdays Project**

Let's enable DCR on UDAP

#### 1. :boom: Apply AddUdapServer extension method to include DCR on UDAP

````csharp
builder.Services.AddIdentityServer()
 .AddUdapServer(
    options =>
        {
            options.DefaultSystemScopes = udapServerOptions.DefaultSystemScopes;
            options.DefaultUserScopes = udapServerOptions.DefaultUserScopes;
            options.ServerSupport = udapServerOptions.ServerSupport;
            options.ForceStateParamOnAuthorizationCode = udapServerOptions.
                orceStateParamOnAuthorizationCode;
        },
    options =>
        options.UdapDbContext = b =>
                b.UseSqlite(connectionString,
                    dbOpts => 
                        dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName))
        );
````

#### 2. :boom: Launch udap.authserver.devdays

#### 3. :boom: Launch UdapEd.Server

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

🗒️ Note: Match is not supported on this sample FHIR server.  

## Advanced

### **🧩 Add Metadata to Firely Server**

## Comments

The Udap.Server package is an implementation of DCR on UDAP.  At the time of writing this package, Identity Server did not have [DCR](https://docs.duendesoftware.com/identityserver/v6/configuration/dcr/) (Dynamic Client Registration).  It has been added in the recent past.   The plan is to revisit this area and see how much of Udap.Server package code can be removed in favor of the Identity Server core DCR API.

## Questions
