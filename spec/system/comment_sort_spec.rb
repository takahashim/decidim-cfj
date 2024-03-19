# frozen_string_literal: true

require "rails_helper"

describe "Comments", :perform_enqueued do
  let!(:component) { create(:debates_component, organization:) }
  let!(:commentable) { create(:debate, :open_ama, component:) }

  let(:resource_path) { resource_locator(commentable).path }

  let!(:organization) { create(:organization) }
  let!(:user) { create(:user, :confirmed, organization:) }
  let!(:comments) { create_list(:comment, 3, commentable:) }

  before do
    switch_to_host(organization.host)

    comment = create(:comment, commentable:, body: "Most Rated Comment")
    create(:comment_vote, comment:, author: user, weight: 1)

    visit decidim.root_path
  end

  it "allows user to store selected comment order in cookies", :slow do
    # click_button "同意します"
    visit resource_path

    expect(page).to have_no_content("Comments are disabled at this time")

    expect(page).to have_css(".comment", minimum: 1)
    page.find(".order-by .dropdown.menu .is-dropdown-submenu-parent").hover

    within ".comments" do
      within ".order-by__dropdown" do
        # click_link "古い順" # Opens the dropdown
        # click_link "評価の高い順"
        page.find_by_id("comments-order-menu-control").click # Opens the dropdown
        page.find("#comments-order-chooser-menu li:first-of-type a").click
      end
    end

    expect(page).to have_css(".comments > div:nth-child(2)", text: "Most Rated Comment")

    # show other page
    visit "/"

    # back to resource page
    visit resource_path

    expect(page).to have_css(".comment", minimum: 1)
    page.find(".order-by .dropdown.menu .is-dropdown-submenu-parent").hover
    # expect(page).to have_css("#comments-order-menu-control", text: "評価の高い順")
    expect(page).to have_css("#comments-order-menu-control", text: "Best rated")
  end
end
