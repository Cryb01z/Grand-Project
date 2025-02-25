using System.Text;

using MongoDB.Driver;

using Microsoft.OpenApi.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;

using ASM_Backend.Repositories;
using ASM_Backend.Interfaces;
using ASM_Backend.Services;
using MongoDB.Bson;

namespace ASM_Backend;

public static class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        
        var connectionString = builder.Configuration["MongoDB:ConnectionString"];
        var databaseName = builder.Configuration["MongoDB:DatabaseName"];

        var client = new MongoClient(connectionString);
        var database = client.GetDatabase(databaseName);
        
        builder.Services.AddSingleton(database);
        
        builder.Services.AddScoped<IUserRepository, UserRepository>();
        builder.Services.AddScoped<ICveRepository, CveRepository>();
        builder.Services.AddScoped<IScanResultRepository, ScanResultRepository>();
        builder.Services.AddScoped<IVariableRepository, VariableRepository>();
        
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy.AllowAnyOrigin()
                    .AllowAnyMethod()
                    .AllowAnyHeader();
            });
        });

        builder.Services.AddHttpClient();
        
        builder.Services.AddControllers();
        
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo { Title = "Example API", Version = "v1" });

            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                BearerFormat = "JWT",
                In = ParameterLocation.Header,
                Scheme = "bearer",
                Description = "Please insert JWT token into field"
            });

            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    []
                }
            });
        });
        
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(o =>
        {
            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = builder.Configuration["Jwt:Issuer"],
                ValidAudience = builder.Configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey
                    (Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Secret"] 
                                            ?? "this is totally a secret key")),
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true
            };
        });
        builder.Services.AddAuthorization();
        
        // Add custom services.
        builder.Services.AddHostedService<CveCrawlJob>();

        var app = builder.Build();
        
        app.UseForwardedHeaders(new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
        });
        
        app.UseCors();
        
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();
        
        //if (app.Environment.IsDevelopment())
        //{
            app.UseSwagger();
            app.UseSwaggerUI();
        //}
        // Test Push

        app.Run();
    }
}