# frozen_string_literal: true

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'frodata/version'

Gem::Specification.new do |spec|
  spec.name          = 'frodata'
  spec.version       = FrOData::VERSION
  spec.authors       = ['Christoph Wagner', 'James Thompson']
  spec.email         = %w{christoph@wrstudios.com james@plainprograms.com}
  spec.summary       = %q{Simple OData library}
  spec.description   = %q{Provides a simple interface for working with OData V4 APIs.}
  spec.homepage      = 'https://github.com/wrstudios/frodata'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = %w{lib}

  spec.required_ruby_version = '>= 3.1.2'

  spec.add_dependency 'faraday',  '~> 2.12'
  spec.add_dependency 'nokogiri', '~> 1.16'
  spec.add_dependency 'andand',   '~> 1.3'

  spec.add_development_dependency 'bundler', '~> 2.2'
  spec.add_development_dependency 'rake', '~> 13'
  spec.add_development_dependency 'simplecov', '~> 0.21'
  spec.add_development_dependency 'rspec', '~> 3.10'
  spec.add_development_dependency 'rspec-autotest'
  spec.add_development_dependency 'autotest', '~> 5.0'
  spec.add_development_dependency 'vcr', "~> 6.0"
  spec.add_development_dependency 'timecop', '~> 0.9'
  spec.add_development_dependency 'equivalent-xml', '~> 0.6'
end
