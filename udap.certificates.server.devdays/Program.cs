var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddDirectoryBrowser();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseStaticFiles();
app.UseDirectoryBrowser();

app.Run();
