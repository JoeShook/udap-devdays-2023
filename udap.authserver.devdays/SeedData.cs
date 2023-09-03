using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.Models;
using Duende.IdentityServer;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Duende.IdentityServer.EntityFramework.Mappers;
using Microsoft.EntityFrameworkCore;
using Udap.Common.Extensions;
using Udap.Model;
using Udap.Server.DbContexts;
using Udap.Server.Entities;
using Udap.Server.Models;
using Udap.Server.Storage.Stores;
using Udap.Util.Extensions;

namespace udap.authserver.devdays;

public static class SeedData
{

    public static async Task InitializeDatabase(IApplicationBuilder app, Serilog.ILogger logger)
    {
        using var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>()!.CreateScope();
        var configDbContext = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
        await configDbContext.Database.MigrateAsync();
        await serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.MigrateAsync();

        await InitializeDatabaseWithUdap(serviceScope, configDbContext, logger);


        //
        // openid
        //
        if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.OpenId))
        {
            var identityResource = new IdentityResources.OpenId();
            configDbContext.IdentityResources.Add(identityResource.ToEntity());

            await configDbContext.SaveChangesAsync();
        }


        //
        // profile
        //
        if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.Profile))
        {
            var identityResource = new IdentityResources.Profile();
            configDbContext.IdentityResources.Add(identityResource.ToEntity());

            await configDbContext.SaveChangesAsync();
        }

    }


    static async Task InitializeDatabaseWithUdap(IServiceScope serviceScope, ConfigurationDbContext configDbContext, Serilog.ILogger logger)
    {
        var udapContext = serviceScope.ServiceProvider.GetRequiredService<UdapDbContext>();
        await udapContext.Database.MigrateAsync();
        var clientRegistrationStore = serviceScope.ServiceProvider.GetRequiredService<IUdapClientRegistrationStore>();

        var assemblyPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        var communities = new List<Tuple<string, X509Certificate2>>();
        var certificateStorePath = "CertificateStore";
        var certificateStoreFullPath = Path.Combine(assemblyPath!, certificateStorePath);

        foreach (var folder in Directory.GetDirectories(certificateStoreFullPath))
        {
            var folderName = new DirectoryInfo(folder).Name;
            var anchorFile = Directory.GetFiles(folder, "*.crt").First();
            var anchorCertificate = new X509Certificate2(anchorFile);
            communities.Add(new Tuple<string, X509Certificate2>(folderName, anchorCertificate));

            logger.Information($"Creating Anchor from: {anchorFile}");
            logger.Information($"Anchor Info: {anchorCertificate.Thumbprint}");
        }

        //
        // Add Communities
        //
        foreach (var communityName in communities.Select(c => c.Item1))
        {
            if (!udapContext.Communities.Any(c => c.Name == communityName))
            {
                var community = new Community { Name = communityName };
                community.Enabled = true;
                community.Default = false;
                udapContext.Communities.Add(community);
                await udapContext.SaveChangesAsync();
            }
        }

        //
        // Load Anchors
        //
        foreach (var communitySeedData in communities)
        {
            var anchorCertificate = communitySeedData.Item2;
            var communityName = communitySeedData.Item1;
            if ((await clientRegistrationStore.GetAnchors(communityName))
                .All(a => a.Thumbprint != anchorCertificate.Thumbprint))
            {

                var community = udapContext.Communities.Single(c => c.Name == communityName);

                var anchor = new Anchor
                {
                    BeginDate = anchorCertificate.NotBefore.ToUniversalTime(),
                    EndDate = anchorCertificate.NotAfter.ToUniversalTime(),
                    Name = anchorCertificate.Subject,
                    Community = community,
                    X509Certificate = anchorCertificate.ToPemFormat(),
                    Thumbprint = anchorCertificate.Thumbprint,
                    Enabled = true
                };

                udapContext.Anchors.Add(anchor);
                await udapContext.SaveChangesAsync();
            }
        }

        await SeedFhirScopes(configDbContext, "patient");
        await SeedFhirScopes(configDbContext, "user");
        await SeedFhirScopes(configDbContext, "system");

        if (configDbContext.IdentityResources.All(i => i.Name != UdapConstants.StandardScopes.FhirUser))
        {
            var fhirUserIdentity = new UdapIdentityResources.FhirUser();
            configDbContext.IdentityResources.Add(fhirUserIdentity.ToEntity());

            configDbContext.SaveChanges();
        }
    }

    static async Task SeedFhirScopes(ConfigurationDbContext configDbContext, string prefix)
    {
        //TODO: needs more thought.  The should be richer than a list of strings. And plenty of constants to code up.
        // And of course there is some kind of Policy engine that should be here.
        var seedScopes = Hl7ModelInfoExtensions.BuildHl7FhirV1AndV2Scopes(prefix);

        var apiScopes = configDbContext.ApiScopes
            .Include(s => s.Properties)
            .Where(s => s.Enabled)
            .Select(s => s)
            .ToList();

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("system")))
        {
            if (!apiScopes.Any(s =>
                    s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "system")))
            {
                var apiScope = new ApiScope(scopeName);
                apiScope.ShowInDiscoveryDocument = false;
                if (apiScope.Name == "system/*.read")
                {
                    apiScope.ShowInDiscoveryDocument = true;
                }
                apiScope.Properties.Add("udap_prefix", "system");
                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("user")))
        {
            if (!apiScopes.Any(s =>
                    s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "user")))
            {
                var apiScope = new ApiScope(scopeName);
                apiScope.ShowInDiscoveryDocument = false;
                if (apiScope.Name == "patient/*.read")
                {
                    apiScope.ShowInDiscoveryDocument = true;
                }
                apiScope.Properties.Add("udap_prefix", "user");
                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        foreach (var scopeName in seedScopes.Where(s => s.StartsWith("patient")))
        {
            if (!apiScopes.Any(s => s.Name == scopeName && s.Properties.Exists(p => p.Key == "udap_prefix" && p.Value == "patient")))
            {
                var apiScope = new ApiScope(scopeName);
                apiScope.ShowInDiscoveryDocument = false;
                if (apiScope.Name == "patient/*.read")
                {
                    apiScope.ShowInDiscoveryDocument = true;
                }
                apiScope.Properties.Add("udap_prefix", "patient");
                configDbContext.ApiScopes.Add(apiScope.ToEntity());
            }
        }

        await configDbContext.SaveChangesAsync();

        if (configDbContext.ApiScopes.All(s => s.Name != "udap"))
        {
            var apiScope = new ApiScope("udap");
            configDbContext.ApiScopes.Add(apiScope.ToEntity());

            await configDbContext.SaveChangesAsync();
        }
    }
}
