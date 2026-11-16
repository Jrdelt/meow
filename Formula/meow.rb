class Meow < Formula
  desc "Local security triage shell, topology mapper & grounded audit workspace"
  homepage "https://github.com/Jrdelt/meow"
  # Tap and install:
  #   brew tap Jrdelt/meow https://github.com/Jrdelt/meow.git
  #   brew trust Jrdelt/meow   # Homebrew 7+
  #   brew install meow        # or `brew install --HEAD meow`
  url "https://github.com/Jrdelt/meow.git", tag: "v0.2.0"
  license "MIT"
  head "https://github.com/Jrdelt/meow.git", branch: "main"

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
      (pkgshare/"wordlists").install "common.txt"
    end
  end

  def caveats
    <<~EOS
       /\\_/\\   meow is installed!
      ( ^w^ )  Run `meow` (or `meow setup`) in a terminal for the interactive
       > ^ <   first-time Cat Setup GUI, or `meow <name>` to open a session.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/meow --version")
  end
end
