using System.Text.Json;
using Hl7.Fhir.DemoFileSystemFhirServer;
using Hl7.Fhir.NetCoreApi;
using Hl7.Fhir.WebApi;
using Microsoft.AspNetCore.Mvc.Formatters;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

var storageDirectory = Path.Combine(Directory.GetCurrentDirectory(), "DemoFileSystemService");

if (!Directory.Exists(storageDirectory))
{
    Directory.CreateDirectory(storageDirectory);
}

DirectorySystemService<IServiceProvider>.Directory = storageDirectory;

builder.Services.AddSingleton<IFhirSystemServiceR4<IServiceProvider>>(_ => {
    var systemService = new DirectorySystemService<IServiceProvider>();
    systemService.InitializeIndexes();
    return systemService;
});

builder.Services
    .UseFhirServerController( /*systemService,*/ options =>
    {
        // An example HTML formatter that puts the raw XML on the output
        options.OutputFormatters.Add(new SimpleHtmlFhirOutputFormatter());
        // need this to serialize udap metadata because UseFhirServerController clears OutputFormatters
        options.OutputFormatters.Add(new SystemTextJsonOutputFormatter(new JsonSerializerOptions()));

    });

// builder.Services.AddUdapMetadataServer(builder.Configuration);

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UsePathBase(new PathString("/fhir/r4"));
app.UseRouting();
// app.UseUdapMetadataServer();

app.UseHttpsRedirection();
app.MapControllers();

app.Run();
