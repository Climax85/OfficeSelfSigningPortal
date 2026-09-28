using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.SigningService;
using OfficeSelfSigningPortal.SigningService.Data;

var builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddDbContext<SigningDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("signing")));

builder.Services.AddHostedService<Worker>();

var app = builder.Build();

await app.RunAsync();
