using Microsoft.Extensions.DependencyInjection;
using MrWho.Endpoints;
using MrWho.Services.Mediator;

namespace MrWho.Extensions;

public static class MediatorServiceCollectionExtensions
{
    public static IServiceCollection AddMrWhoMediator(this IServiceCollection services)
    {
    services.AddScoped<IMediator, Mediator>();

        // Register endpoint handlers
        services.AddTransient<IRequestHandler<OidcAuthorizeRequest, IResult>, OidcAuthorizeHandler>();
        services.AddTransient<IRequestHandler<OidcTokenRequest, IResult>, OidcTokenHandler>();
        services.AddTransient<IRequestHandler<OidcLogoutRequest, IResult>, OidcLogoutHandler>();
        services.AddTransient<IRequestHandler<UserInfoRequest, IResult>, UserInfoHandler>();

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
    services.AddTransient<IRequestHandler<UserInfoTestRequest, IResult>, UserInfoTestHandler>();
    services.AddTransient<IRequestHandler<CurrentClaimsRequest, IResult>, CurrentClaimsHandler>();
    services.AddTransient<IRequestHandler<IdentityResourcesRequest, IResult>, IdentityResourcesHandler>();
    services.AddTransient<IRequestHandler<UserClaimsByUserIdRequest, IResult>, UserClaimsByUserIdHandler>();
    services.AddTransient<IRequestHandler<AllUsersRequest, IResult>, AllUsersHandler>();
    services.AddTransient<IRequestHandler<FindUserBySubjectRequest, IResult>, FindUserBySubjectHandler>();
    services.AddTransient<IRequestHandler<CheckSpecificSubjectRequest, IResult>, CheckSpecificSubjectHandler>();
    services.AddTransient<IRequestHandler<Demo1TroubleshootRequest, IResult>, Demo1TroubleshootHandler>();

        return services;
    }
}
