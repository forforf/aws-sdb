gem_spec = Gem::Specification.new do |s|
  s.name = "forforf-aws-sdb"
  s.rubyforge_project = s.name
  s.version = "0.1.0"
  s.has_rdoc = false
  s.extra_rdoc_files = ["README", "LICENSE"]
  s.summary = "Amazon SDB API"
  s.description = s.summary
  s.author = "Dave M"
  s.email = "dmarti21@gmail.com"
  s.homepage = "http://github.com/forforf/aws-sdb"
  s.add_dependency "uuidtools"
  s.require_path = 'lib'
  s.files = %w(LICENSE README Rakefile) + Dir.glob("{lib,spec}/**/*")
end
