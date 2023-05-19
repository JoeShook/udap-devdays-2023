using Duende.IdentityServer.EntityFramework.Stores;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using udap.authserver.devdays;

var builder = WebApplication.CreateBuilder(args);

const string connectionString = @"Data Source=udap.authserver.devdays.EntityFramework.db";

// Add services to the container.

builder.Services.AddRazorPages();
builder.Services.AddIdentityServer()
    .AddConfigurationStore(options =>
        {
            options.ConfigureDbContext = b =>
                b.UseSqlite(connectionString,
                    dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));
        }
    )
    .AddOperationalStore(options =>
    {
        options.ConfigureDbContext = b =>
            b.UseSqlite(connectionString,
                dbOpts => dbOpts.MigrationsAssembly(typeof(Program).Assembly.FullName));

    })
    .AddResourceStore<ResourceStore>()
    .AddClientStore<ClientStore>()
    .AddTestUsers(TestUsers.Users);

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.Run();
