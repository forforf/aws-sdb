gem_spec = Gem::Specification.new do |s|
  s.name = "forforf-aws-sdb"
  s.rubyforge_project = s.name
  s.version = "0.5.2"
  s.date = %q{2010-12-26}
  s.description = %q{Update to the aws-sdb gem to support current AWS SimpleDB interface}
  s.has_rdoc = false
  s.extra_rdoc_files = ["README", "LICENSE"]
  s.summary = "Amazon SDB API"
  s.authors = ["Tim Dysinger", "Dave M"]
  s.email = "dmarti21@gmail.com"
  s.homepage = "http://github.com/forforf/aws-sdb"
  s.add_dependency "uuidtools"
  s.add_dependency "curb-fu", ">= 0.4.4"
  s.require_path = 'lib'
  s.files = %w(LICENSE README Rakefile) + Dir.glob("{lib,spec}/**/*")
end
