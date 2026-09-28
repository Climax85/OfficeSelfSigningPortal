using Microsoft.EntityFrameworkCore;
using OfficeSelfSigningPortal.WorkerService;
using OfficeSelfSigningPortal.WorkerService.Data;

var builder = Host.CreateApplicationBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddDbContext<WorkerDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("worker")));

builder.Services.AddHostedService<Worker>();

var app = builder.Build();

await app.RunAsync();
