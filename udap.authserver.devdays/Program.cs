using Duende.IdentityServer.EntityFramework.Stores;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.Models;
using Duende.IdentityServer;
using Duende.IdentityServer.EntityFramework.Mappers;
using udap.authserver.devdays.Pages;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((ctx, lc) => lc
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
    .Enrich.FromLogContext()
    .ReadFrom.Configuration(ctx.Configuration));

var migrationsAssembly = typeof(Program).Assembly.GetName().Name;
const string connectionString = @"Data Source=udap.authserver.devdays.EntityFramework.db";

//
// Add services to the container.
//

builder.Services.AddRazorPages();
builder.Services.AddIdentityServer()
    .AddConfigurationStore(options => 
    {
        options.ConfigureDbContext = b => b.UseSqlite(connectionString,
            dbOpts => dbOpts.MigrationsAssembly(migrationsAssembly));
    })
    .AddOperationalStore(options => 
    {
        options.ConfigureDbContext = b => b.UseSqlite(connectionString,
            dbOpts => dbOpts.MigrationsAssembly(migrationsAssembly));

    })
    .AddResourceStore<ResourceStore>()
    .AddClientStore<ClientStore>()
    .AddTestUsers(TestUsers.Users);

var app = builder.Build();


//
// Configure the HTTP request pipeline.
//

app.UseSerilogRequestLogging();
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

InitializeDatabase(app);

app.UseStaticFiles();
app.UseRouting();

app.UseIdentityServer();

app.UseAuthorization();
app.MapRazorPages().RequireAuthorization();

app.Run();

static void InitializeDatabase(IApplicationBuilder app)
{
    using var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>()!.CreateScope();
    var configDbContext = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
    configDbContext.Database.Migrate();
    serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

    // await SeedFhirScopes(configDbContext, "patient");
    // await SeedFhirScopes(configDbContext, "user");
    // await SeedFhirScopes(configDbContext, "system");

    //
    // openid
    //
    if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.OpenId))
    {
        var identityResource = new IdentityResources.OpenId();
        configDbContext.IdentityResources.Add(identityResource.ToEntity());

        configDbContext.SaveChanges();
    }

    // if (configDbContext.IdentityResources.All(i => i.Name != UdapConstants.StandardScopes.FhirUser))
    // {
    //     var fhirUserIdentity = new UdapIdentityResources.FhirUser();
    //     configDbContext.IdentityResources.Add(fhirUserIdentity.ToEntity());
    //
    //      configDbContext.SaveChanges();
    // }

    //
    // profile
    //
    if (configDbContext.IdentityResources.All(i => i.Name != IdentityServerConstants.StandardScopes.Profile))
    {
        var identityResource = new IdentityResources.Profile();
        configDbContext.IdentityResources.Add(identityResource.ToEntity());

        configDbContext.SaveChanges();
    }

}