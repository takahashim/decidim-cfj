# frozen_string_literal: true

require "rails_helper"

# Covers config/initializers/oauth_client_organization_override.rb.
RSpec.describe "OAuth clients of the organization" do
  include Devise::Test::IntegrationHelpers

  let(:organization) { create(:organization) }
  let(:other_organization) { create(:organization) }
  let(:user) { create(:user, :confirmed, organization:) }
  let(:other_user) { create(:user, :confirmed, organization: other_organization) }
  let(:own_application) { create(:oauth_application, organization:, name: "Own OAuth application") }
  let(:other_application) { create(:oauth_application, organization: other_organization, name: "Other OAuth application") }

  before do
    host! organization.host
  end

  def authorize_params(application)
    { client_id: application.uid, redirect_uri: application.redirect_uri, response_type: "code", scope: "public" }
  end

  def bearer(token)
    { "Authorization" => "Bearer #{token}", "Accept" => "application/json" }
  end

  describe "authorization request" do
    before do
      sign_in user, scope: :user
    end

    context "when the client belongs to the organization" do
      before { get "/oauth/authorize", params: authorize_params(own_application) }

      it "asks the user to authorize the client" do
        expect(response).to have_http_status(:ok)
        expect(response.body).to include("Own OAuth application")
      end
    end

    context "when the client belongs to another organization" do
      let(:invalid_client_message) do
        ERB::Util.html_escape(I18n.t("doorkeeper.errors.messages.invalid_client", locale: organization.default_locale))
      end

      it "answers as for an unknown client" do
        get "/oauth/authorize", params: authorize_params(other_application)

        expect(response).to have_http_status(:unauthorized)
        expect(response.body).to include(invalid_client_message)
        expect(response.body).not_to include("Other OAuth application")

        get "/oauth/authorize", params: authorize_params(other_application).merge(client_id: "unknown")

        expect(response).to have_http_status(:unauthorized)
        expect(response.body).to include(invalid_client_message)
      end

      it "does not issue a grant" do
        post "/oauth/authorize", params: authorize_params(other_application)

        expect(response).to have_http_status(:unauthorized)
        expect(Doorkeeper::AccessGrant.where(application_id: other_application.id)).to be_empty
      end
    end

    describe "denial" do
      let(:evil_uri) { "https://evil.example.com/callback" }

      it "redirects back to the client of the organization" do
        delete "/oauth/authorize", params: authorize_params(own_application)

        expect(response).to have_http_status(:redirect)
        expect(response.location).to start_with(own_application.redirect_uri)
        expect(response.location).to include("error=access_denied")
      end

      it "does not redirect for a client of another organization" do
        delete "/oauth/authorize", params: authorize_params(other_application).merge(redirect_uri: evil_uri)

        expect(response).to have_http_status(:unauthorized)
        expect(response.location).to be_nil
      end

      it "does not redirect for an unknown client" do
        delete "/oauth/authorize", params: authorize_params(own_application).merge(client_id: "unknown", redirect_uri: evil_uri)

        expect(response).to have_http_status(:unauthorized)
        expect(response.location).to be_nil
      end

      it "does not redirect to a redirect URI the client did not register" do
        delete "/oauth/authorize", params: authorize_params(own_application).merge(redirect_uri: evil_uri)

        expect(response).not_to have_http_status(:redirect)
        expect(response.location).to be_nil
      end
    end
  end

  describe "authorization code flow of a client of the organization" do
    before do
      sign_in user, scope: :user
    end

    it "returns the user data" do
      post "/oauth/authorize", params: authorize_params(own_application)
      expect(response).to have_http_status(:redirect)
      code = Rack::Utils.parse_query(URI.parse(response.location).query)["code"]
      expect(code).to be_present

      post "/oauth/token", params: {
        grant_type: "authorization_code",
        code:,
        client_id: own_application.uid,
        client_secret: own_application.secret,
        redirect_uri: own_application.redirect_uri
      }
      expect(response).to have_http_status(:ok)

      get "/oauth/me", headers: bearer(response.parsed_body["access_token"])
      expect(response).to have_http_status(:ok)
      expect(response.parsed_body["email"]).to eq(user.email)
    end
  end

  describe "token request" do
    def request_token(application)
      post "/oauth/token", params: { grant_type: "client_credentials", client_id: application.uid, client_secret: application.secret }
    end

    context "when the client belongs to the organization" do
      it "issues a token" do
        request_token(own_application)

        expect(response).to have_http_status(:ok)
        expect(response.parsed_body["access_token"]).to be_present
      end
    end

    context "when the client belongs to another organization" do
      it "rejects the client" do
        request_token(other_application)

        expect(response).to have_http_status(:unauthorized)
        expect(response.parsed_body["error"]).to eq("invalid_client")
        expect(response.headers["WWW-Authenticate"]).to include("invalid_client")
        expect(Doorkeeper::AccessToken.where(application_id: other_application.id)).to be_empty
      end
    end
  end

  describe "token revocation" do
    let!(:token) { create(:oauth_access_token, application: other_application, resource_owner_id: other_user.id) }

    it "rejects a client of another organization" do
      post "/oauth/revoke", params: { token: token.token, client_id: other_application.uid, client_secret: other_application.secret }

      expect(response).to have_http_status(:unauthorized)
      expect(token.reload).not_to be_revoked
    end
  end

  describe "user data of a token" do
    before { get "/oauth/me", headers: bearer(token.token) }

    context "when the token was issued to a client of the organization" do
      let(:token) { create(:oauth_access_token, application: own_application, resource_owner_id: user.id) }

      it "returns the user data" do
        expect(response).to have_http_status(:ok)
        expect(response.parsed_body["email"]).to eq(user.email)
      end
    end

    shared_examples "an invalid token" do
      it "does not return the user data" do
        expect(response).to have_http_status(:unauthorized)
        expect(response.headers["WWW-Authenticate"]).to include("invalid_token")
        expect(response.body).not_to include(other_user.email)
      end
    end

    context "when the token was issued to a client of another organization" do
      let(:token) { create(:oauth_access_token, application: other_application, resource_owner_id: other_user.id) }

      it_behaves_like "an invalid token"
    end

    context "when the token belongs to a user of another organization" do
      let(:token) { create(:oauth_access_token, application: own_application, resource_owner_id: other_user.id) }

      it_behaves_like "an invalid token"
    end

    context "when the token has no resource owner" do
      let(:token) { create(:oauth_access_token, application: own_application, resource_owner_id: nil) }

      it_behaves_like "an invalid token"
    end
  end

  describe "token info" do
    before { get "/oauth/token/info", headers: bearer(token.token) }

    context "when the token was issued to a client of the organization" do
      let(:token) { create(:oauth_access_token, application: own_application, resource_owner_id: user.id) }

      it "returns the token info" do
        expect(response).to have_http_status(:ok)
        expect(response.parsed_body["application"]).to include("uid" => own_application.uid)
      end
    end

    context "when the token was issued to a client of another organization" do
      let(:token) { create(:oauth_access_token, application: other_application, resource_owner_id: other_user.id) }

      it "does not return the token info" do
        expect(response).to have_http_status(:unauthorized)
        expect(response.body).not_to include(other_application.uid)
      end
    end
  end
end
