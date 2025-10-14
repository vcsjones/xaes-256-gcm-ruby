$:.unshift File.expand_path('../lib', __FILE__)
require "xaes_256_gcm/version"

Gem::Specification.new do |s|
  s.name = "xaes_256_gcm"
  s.summary = "Implements the XAES-256-GCM algorithm."
  s.version = Xaes256Gcm::VERSION
  s.license = "MIT"
  s.homepage = "https://github.com/vcsjones/xaes_256_gcm"
  s.authors = ["vcsjones"]
  s.email = "kevin@vcsjones.dev"
  s.required_ruby_version = ">= 2.7"
  s.files = Dir["./lib/**/*.rb"] + ["./LICENSE.md"]

  s.add_development_dependency "rspec", "~> 3.13"
end
