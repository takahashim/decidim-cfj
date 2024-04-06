# frozen_string_literal: true

source "https://rubygems.org"

ruby RUBY_VERSION

gem "decidim", "0.28.0"

gem "decidim-decidim_awesome", git: "https://github.com/codeforjapan/decidim-module-decidim_awesome.git", branch: "develop"

gem "decidim-term_customizer", git: "https://github.com/codeforjapan/decidim-module-term_customizer.git", branch: "028-ja"

gem "decidim-navigation_maps", git: "https://github.com/codeforjapan/decidim-module-navigation_maps.git", branch: "upgrade-0.28-2024-04-03"
# gem "decidim-polis", git: "https://github.com/codeforjapan/decidim-polis.git", branch: "update-0-27-4"

gem "bootsnap"

gem "puma", ">= 6.3.1"
gem "puma_worker_killer"

gem "faker", "~> 3.2"

gem "wicked_pdf", "~> 2.1"

gem "deface"
gem "image_processing"
gem "newrelic_rpm"

gem "omniauth-line_login", path: "omniauth-line_login"
gem "omniauth-rails_csrf_protection"

# gem "decidim-user_extension", path: "decidim-user_extension"

gem "slack-ruby-client"

group :development, :test do
  gem "byebug", "~> 11.0", platform: :mri
  gem "figaro"

  gem "decidim-dev", "0.28.0"
  gem "dotenv-rails"
  gem "factory_bot_rails"
  gem "rspec-rails"
end

group :development do
  gem "letter_opener_web"
  gem "listen", "~> 3.1"
  gem "rubocop-faker"
  gem "spring"
  gem "spring-watcher-listen"
  gem "web-console", "~> 4.2"
end

group :production do
  gem "aws-sdk-s3", require: false
  # gem "aws-xray-sdk", require: ["aws-xray-sdk/facets/rails/railtie"]
  gem "fog-aws"
  # gem "oj", platform: :mri
  gem "sidekiq", "6.5.12"
end

gem "rubyzip", ">= 1.0.0"
gem "zip-zip"
