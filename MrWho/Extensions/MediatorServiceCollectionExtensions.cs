using Microsoft.Extensions.DependencyInjection;
using MrWho.Endpoints;
using MrWho.Services.Mediator;
using Microsoft.AspNetCore.Mvc; // added

namespace MrWho.Extensions;

public static class MediatorServiceCollectionExtensions
{
    public static IServiceCollection AddMrWhoMediator(this IServiceCollection services)
    {
    services.AddScoped<IMediator, Mediator>();

        // Register endpoint handlers
        services.AddTransient<IRequestHandler<OidcAuthorizeRequest, IResult>, MrWho.Handlers.Oidc.OidcAuthorizeHandler>();
        services.AddTransient<IRequestHandler<OidcTokenRequest, IResult>, MrWho.Handlers.Oidc.OidcTokenHandler>();
        services.AddTransient<IRequestHandler<OidcLogoutRequest, IResult>, MrWho.Handlers.Oidc.OidcLogoutHandler>();

        // Auth handlers
        services.AddTransient<IRequestHandler<MrWho.Endpoints.Auth.LoginGetRequest, IActionResult>, MrWho.Handlers.Auth.LoginGetHandler>();
        services.AddTransient<IRequestHandler<MrWho.Endpoints.Auth.LoginPostRequest, IActionResult>, MrWho.Handlers.Auth.LoginPostHandler>();
        services.AddTransient<IRequestHandler<MrWho.Endpoints.Auth.LogoutGetRequest, IActionResult>, MrWho.Handlers.Auth.LogoutGetHandler>();
        services.AddTransient<IRequestHandler<MrWho.Endpoints.Auth.LogoutPostRequest, IActionResult>, MrWho.Handlers.Auth.LogoutPostHandler>();
        services.AddTransient<IRequestHandler<MrWho.Endpoints.Auth.AccessDeniedGetRequest, IActionResult>, MrWho.Handlers.Auth.AccessDeniedGetHandler>();
        services.AddTransient<IRequestHandler<MrWho.Endpoints.Auth.RegisterGetRequest, IActionResult>, MrWho.Handlers.Auth.RegisterGetHandler>();
        services.AddTransient<IRequestHandler<MrWho.Endpoints.Auth.RegisterPostRequest, IActionResult>, MrWho.Handlers.Auth.RegisterPostHandler>();
        services.AddTransient<IRequestHandler<MrWho.Endpoints.Auth.RegisterSuccessGetRequest, IActionResult>, MrWho.Handlers.Auth.RegisterSuccessGetHandler>();

    // Debug endpoint handlers
    services.AddTransient<IRequestHandler<DebugIndexRequest, IResult>, DebugIndexHandler>();
    services.AddTransient<IRequestHandler<ClientCookiesDebugRequest, IResult>, ClientCookiesDebugHandler>();
    services.AddTransient<IRequestHandler<ClientInfoRequest, IResult>, ClientInfoHandler>();
    services.AddTransient<IRequestHandler<DbClientConfigRequest, IResult>, DbClientConfigHandler>();
    services.AddTransient<IRequestHandler<AdminClientInfoRequest, IResult>, AdminClientInfoHandler>();
    services.AddTransient<IRequestHandler<Demo1ClientInfoRequest, IResult>, Demo1ClientInfoHandler>();
    services.AddTransient<IRequestHandler<EssentialDataRequest, IResult>, EssentialDataHandler>();
    services.AddTransient<IRequestHandler<ClientPermissionsRequest, IResult>, ClientPermissionsHandler>();
    services.AddTransient<IRequestHandler<ResetAdminClientRequest, IResult>, ResetAdminClientHandler>();
    services.AddTransient<IRequestHandler<FixApiPermissionsRequest, IResult>, FixApiPermissionsHandler>();
    services.AddTransient<IRequestHandler<OpenIddictScopesRequest, IResult>, OpenIddictScopesHandler>();
    services.AddTransient<IRequestHandler<SyncScopesRequest, IResult>, SyncScopesHandler>();
    services.AddTransient<IRequestHandler<CurrentClaimsRequest, IResult>, CurrentClaimsHandler>();
    services.AddTransient<IRequestHandler<IdentityResourcesRequest, IResult>, IdentityResourcesHandler>();
    services.AddTransient<IRequestHandler<UserClaimsByUserIdRequest, IResult>, UserClaimsByUserIdHandler>();
    services.AddTransient<IRequestHandler<AllUsersRequest, IResult>, AllUsersHandler>();
    services.AddTransient<IRequestHandler<FindUserBySubjectRequest, IResult>, FindUserBySubjectHandler>();
    services.AddTransient<IRequestHandler<CheckSpecificSubjectRequest, IResult>, CheckSpecificSubjectHandler>();
    services.AddTransient<IRequestHandler<Demo1TroubleshootRequest, IResult>, Demo1TroubleshootHandler>();
    services.AddTransient<IRequestHandler<ResyncClientsRequest, IResult>, ResyncClientsHandler>();

        return services;
    }
}
