module Frodo
  # Authentication middleware used if client_id, client_secret, and client_credentials: true are set
  class Middleware::Authentication::FADAL < Frodo::Middleware::Authentication
    def authenticate!
      ctx = ADAL::AuthenticationContext.new(::ADAL::Authority::WORLD_WIDE_AUTHORITY)
      user_cred = ADAL::UserCredential.new(@options[:username], @options[:password])
      tk = ctx.acquire_token_for_user(@options[:instance_url], @options[:client_id], user_cred)

      case tk
      when ADAL::SuccessResponse
        @options[:oauth_token] = tk.access_token
        @options[:refresh_token] = tk.refresh_token
        @options[:authentication_callback]&.call(tk)
      when ADAL::ErrorResponse
        raise Frodo::AuthenticationError, tk.error_description
      else
        raise 'Adal wtf'
      end
    end
  end
end
