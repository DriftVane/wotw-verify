# Initial seed for 3030-Labs/homebrew-tap Formula/wotw-verify.rb.
#
# Once the release workflow runs against v0.1.0, GoReleaser will
# auto-update this file in the homebrew-tap repo with the real URLs +
# SHA-256 digests. This seed file exists so:
#
#  1. A reviewer can sanity-check the formula shape before tagging.
#  2. If the auto-update fails, an operator can manually copy this
#     file into the tap repo and patch the URLs.
#
# The placeholders below MUST be replaced before publishing.
class WotwVerify < Formula
  desc "Customer-verifiable trust primitive for wotw Compliance Packs"
  homepage "https://github.com/3030-Labs/wotw-verify"
  license "Apache-2.0"
  version "0.1.1"

  on_macos do
    on_arm do
      url "https://github.com/3030-Labs/wotw-verify/releases/download/v#{version}/wotw-verify_#{version}_darwin_arm64.tar.gz"
      sha256 "REPLACE_WITH_REAL_SHA256_AT_RELEASE_TIME"
    end
    on_intel do
      url "https://github.com/3030-Labs/wotw-verify/releases/download/v#{version}/wotw-verify_#{version}_darwin_x86_64.tar.gz"
      sha256 "REPLACE_WITH_REAL_SHA256_AT_RELEASE_TIME"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/3030-Labs/wotw-verify/releases/download/v#{version}/wotw-verify_#{version}_linux_arm64.tar.gz"
      sha256 "REPLACE_WITH_REAL_SHA256_AT_RELEASE_TIME"
    end
    on_intel do
      url "https://github.com/3030-Labs/wotw-verify/releases/download/v#{version}/wotw-verify_#{version}_linux_x86_64.tar.gz"
      sha256 "REPLACE_WITH_REAL_SHA256_AT_RELEASE_TIME"
    end
  end

  def install
    bin.install "wotw-verify"
    doc.install "README.md", "LICENSE"
    (doc/"docs").install Dir["docs/*"]
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/wotw-verify --version")
    # Embedded self-test exercises the 5 fixture scenarios.
    system bin/"wotw-verify", "--self-test"
  end
end
