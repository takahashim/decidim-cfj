# frozen_string_literal: true

# Binds OAuth clients and access tokens to the organization of the requested
# host.
#
# Doorkeeper resolves applications and tokens globally, so an application
# registered in one organization is also accepted on another organization's
# host. Here an application or token of another organization is treated the
# same as an unknown one, so Doorkeeper answers with its regular errors:
#
# - GET/POST/DELETE /oauth/authorize: the client is resolved among the
#   applications of the current organization (invalid_client error page).
#   DELETE (deny) is validated like GET and POST before it redirects.
# - POST /oauth/token, /oauth/revoke, /oauth/introspect: client credentials of
#   an application of another organization are rejected (401 invalid_client).
#   This covers every grant, including refresh_token, which looks the client
#   up on its own instead of through Doorkeeper::Server#client.
# - GET /oauth/me, /oauth/token/info: a token issued to an application of
#   another organization, or to a user of another organization, is no token
#   (401 invalid_token with WWW-Authenticate). /oauth/me also requires a
#   resource owner, which client_credentials tokens do not have.
#
# /oauth/introspect authenticated by a bearer token instead of client
# credentials is left as is: Doorkeeper's default allow_token_introspection
# only lets a token introspect tokens of its own application.
module DecidimCfjOAuthOrganizationScope
  def self.application?(application, organization)
    organization.present? && application.present? && application.decidim_organization_id == organization.id
  end

  def self.token?(token, organization, resource_owner_required: false)
    return false unless token && application?(token.application, organization)
    return !resource_owner_required if token.resource_owner_id.nil?

    organization.users.exists?(id: token.resource_owner_id)
  end
end

Rails.application.config.to_prepare do
  Decidim::Doorkeeper::AuthorizationsController # rubocop:disable Lint/Void
  Decidim::Doorkeeper::CredentialsController # rubocop:disable Lint/Void

  # Extends one Doorkeeper::OAuth::PreAuthorization instance. A subclass would
  # not work: Doorkeeper::Validations keeps the validations in a class-level
  # instance variable, so a subclass would run none of them.
  module DecidimCfjOrganizationPreAuthorization
    attr_accessor :decidim_organization

    private

    def validate_client
      @client = Doorkeeper::OAuth::Client.find(client_id, ->(uid) { decidim_organization&.oauth_applications&.find_by(uid:) })
      @client.present?
    end
  end

  module DecidimDoorkeeperAuthorizationsOrganizationPatch
    def oauth_application
      pre_auth.client&.application
    end

    # Doorkeeper answers a denial with a redirect to the requested redirect_uri
    # without validating the request first, so an unknown client (and now a
    # client of another organization) would redirect anywhere.
    def destroy
      return render_error unless pre_auth.authorizable?

      super
    end

    private

    def pre_auth
      @pre_auth ||= super.extend(DecidimCfjOrganizationPreAuthorization).tap do |pre_auth|
        pre_auth.decidim_organization = current_organization
      end
    end
  end

  module DecidimDoorkeeperCredentialsOrganizationPatch
    private

    def doorkeeper_token
      return @doorkeeper_token if defined?(@doorkeeper_token)

      token = super
      @doorkeeper_token = (token if DecidimCfjOAuthOrganizationScope.token?(token, current_organization, resource_owner_required: true))
    end
  end

  module DecidimCfjDoorkeeperTokenInfoOrganizationPatch
    private

    def doorkeeper_token
      return @doorkeeper_token if defined?(@doorkeeper_token)

      token = super
      @doorkeeper_token = (token if DecidimCfjOAuthOrganizationScope.token?(token, request.env["decidim.current_organization"]))
    end
  end

  module DecidimCfjDoorkeeperTokensOrganizationPatch
    def self.prepended(base)
      base.prepend_before_action :reject_client_of_other_organization
    end

    private

    def reject_client_of_other_organization
      uid = server.credentials&.uid
      return if uid.blank?

      application = Doorkeeper.config.application_model.by_uid(uid)
      return if application.nil? || DecidimCfjOAuthOrganizationScope.application?(application, request.env["decidim.current_organization"])

      error = Doorkeeper::OAuth::ErrorResponse.new(name: :invalid_client)
      headers.merge!(error.headers)
      render json: error.body, status: error.status
    end
  end

  Decidim::Doorkeeper::AuthorizationsController.prepend(DecidimDoorkeeperAuthorizationsOrganizationPatch)
  Decidim::Doorkeeper::CredentialsController.prepend(DecidimDoorkeeperCredentialsOrganizationPatch)
  Doorkeeper::TokenInfoController.prepend(DecidimCfjDoorkeeperTokenInfoOrganizationPatch)
  Doorkeeper::TokensController.prepend(DecidimCfjDoorkeeperTokensOrganizationPatch)
end
