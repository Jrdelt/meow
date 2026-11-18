class Meow < Formula
  desc "Local security triage shell, topology mapper & grounded audit workspace"
  homepage "https://github.com/Jrdelt/meow"
  # Tap and install:
  #   brew tap Jrdelt/meow https://github.com/Jrdelt/meow.git
  #   brew trust Jrdelt/meow   # Homebrew 7+
  #   brew install meow        # or `brew install --HEAD meow`
  url "https://github.com/Jrdelt/meow.git", tag: "v0.2.3"
  license "MIT"
  head "https://github.com/Jrdelt/meow.git", branch: "main"

  depends_on "rust" => :build
  depends_on "feroxbuster"
  depends_on "katana"
  depends_on "nmap"

  resource "seclists_common" do
    url "https://raw.githubusercontent.com/danielmiessler/SecLists/0c618cfc28d1e68811b95c61cc9ab05bc10b0a02/Discovery/Web-Content/common.txt"
    sha256 "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a"
  end

  def install
    system "cargo", "install", *std_cargo_args
    resource("seclists_common").stage do
      (pkgshare/"wordlists").install "common.txt"
    end
  end

  def caveats
    <<~EOS
       /\\_/\\   meow is installed!
      ( ^w^ )  Run `meow` (or `meow setup`) in a terminal for the interactive
       > ^ <   first-time Cat Setup GUI, or `meow <name>` to open a session.
               Run `meow tools` any time to install the offline location database.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/meow --version")
  end
end
