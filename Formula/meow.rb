class Meow < Formula
  desc "Local security triage shell, topology mapper & grounded audit workspace"
  homepage "https://github.com/Jrdelt/meow"
  version "0.1.0"
  license "MIT"

  # For installing from a local checkout (`brew install --HEAD ./Formula/meow.rb`)
  # or a tapped repository (`brew tap <owner>/meow <git-url> && brew install --HEAD meow`).
  head Pathname.new(__dir__).parent.realpath.to_s, using: :git

  depends_on "rust" => :build
  depends_on "feroxbuster"
  depends_on "katana"
  depends_on "nmap"

  resource "seclists_common" do
    url "https://raw.githubusercontent.com/danielmiessler/SecLists/f68bef9c49622d9f76c7cae7a8c2dae24da2d236/Discovery/Web-Content/common.txt"
    sha256 "78e7be2efbbbfef8ef1eb02116189087fd9205ef2bf997e68b29b45bfeb8ab52"
  end

  def install
    system "cargo", "install", *std_cargo_args
    resource("seclists_common").stage do
      (share/"seclists/Discovery/Web-Content").install "common.txt"
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/meow --version")
  end
end
