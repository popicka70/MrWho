// Authentication Error Handler for Blazor
window.mrWhoAuth = {
    // Monitor fetch requests for authentication errors
    initializeAuthMonitoring: function() {
        const originalFetch = window.fetch;
        
        window.fetch = async function(...args) {
            try {
                const response = await originalFetch(...args);
                
                // Check for authentication errors
                if (response.status === 403 || response.status === 401) {
                    const authError = response.headers.get('X-Auth-Error');
                    const authErrorDescription = response.headers.get('X-Auth-Error-Description');
                    const authErrorRedirect = response.headers.get('X-Auth-Error-Redirect');
                    
                    if (authError === 'session_revoked' || response.status === 403) {
                        console.warn('Authentication error detected:', {
                            status: response.status,
                            authError: authError,
                            description: authErrorDescription,
                            url: args[0]
                        });
                        
                        // Use custom redirect URL if provided, otherwise build default
                        const errorUrl = authErrorRedirect || 
                            `/auth/error?error=${encodeURIComponent(authError || 'access_denied')}&error_description=${encodeURIComponent(authErrorDescription || 'Session expired or access denied')}&status_code=${response.status}`;
                        
                        // Small delay to allow any pending operations to complete
                        setTimeout(() => {
                            console.log('Redirecting to authentication error page:', errorUrl);
                            window.location.href = errorUrl;
                        }, 1000);
                    }
                }
                
                return response;
            } catch (error) {
                console.error('Fetch error:', error);
                throw error;
            }
        };
        
        // Also monitor XMLHttpRequest for compatibility with older code
        const originalXHROpen = XMLHttpRequest.prototype.open;
        const originalXHRSend = XMLHttpRequest.prototype.send;
        
        XMLHttpRequest.prototype.open = function(method, url, ...rest) {
            this._url = url;
            return originalXHROpen.call(this, method, url, ...rest);
        };
        
        XMLHttpRequest.prototype.send = function(...args) {
            this.addEventListener('load', function() {
                if (this.status === 403 || this.status === 401) {
                    const authError = this.getResponseHeader('X-Auth-Error');
                    const authErrorRedirect = this.getResponseHeader('X-Auth-Error-Redirect');
                    
                    if (authError === 'session_revoked' || this.status === 403) {
                        console.warn('XHR Authentication error detected:', {
                            status: this.status,
                            authError: authError,
                            url: this._url
                        });
                        
                        const errorUrl = authErrorRedirect || 
                            `/auth/error?error=access_denied&status_code=${this.status}`;
                        
                        setTimeout(() => {
                            window.location.href = errorUrl;
                        }, 1000);
                    }
                }
            });
            
            return originalXHRSend.call(this, ...args);
        };
    },
    
    // Monitor Blazor Server errors specifically
    initializeBlazorMonitoring: function() {
        // Listen for Blazor circuit errors that might indicate authentication issues
        if (window.Blazor) {
            window.Blazor.start({
                circuit: {
                    configureSignalR: function (builder) {
                        builder.onclose(function (error) {
                            if (error && error.message && error.message.includes('401') || error.message.includes('403')) {
                                console.warn('Blazor circuit closed due to authentication error:', error);
                                setTimeout(() => {
                                    window.location.href = '/auth/error?error=blazor_circuit_closed&status_code=403';
                                }, 2000);
                            }
                        });
                    }
                }
            });
        }
    },
    
    // Force logout and redirect
    forceLogout: function() {
        console.log('Forcing logout and clearing all authentication');
        window.location.href = '/auth/logout?clearAll=true';
    },
    
    // Redirect to login with current page as return URL
    redirectToLogin: function() {
        const returnUrl = encodeURIComponent(window.location.pathname + window.location.search);
        console.log('Redirecting to login with return URL:', returnUrl);
        window.location.href = `/auth/logout?returnUrl=/login?returnUrl=${returnUrl}`;
    },
    
    // Manual error page navigation (for use from error components)
    goToErrorPage: function(error, description, statusCode) {
        const errorUrl = `/auth/error?error=${encodeURIComponent(error || 'unknown_error')}&error_description=${encodeURIComponent(description || 'An authentication error occurred')}&status_code=${statusCode || '500'}`;
        window.location.href = errorUrl;
    }
};

// Initialize monitoring when the script loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing MrWho authentication monitoring');
    window.mrWhoAuth.initializeAuthMonitoring();
    
    // Initialize Blazor monitoring after a short delay to ensure Blazor is loaded
    setTimeout(() => {
        window.mrWhoAuth.initializeBlazorMonitoring();
    }, 1000);
});

// Also initialize immediately in case DOM is already loaded
if (document.readyState !== 'loading') {
    console.log('DOM already loaded, initializing MrWho authentication monitoring immediately');
    window.mrWhoAuth.initializeAuthMonitoring();
    
    // Initialize Blazor monitoring after a short delay
    setTimeout(() => {
        window.mrWhoAuth.initializeBlazorMonitoring();
    }, 1000);
}