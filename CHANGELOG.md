# CHANGELOG

## unreleased

* response type check returns boolean instead integer
* Broken properties (FrOData::Properties::Double) tests fixed
* Development dependencies updated
* Nokogiri gem updated to v1.12.x
* Faraday gem updated to v1.8.x
* Require Ruby 2.6+ in gemspec

## 0.9.3

* Fix broken stack traces in response errors
* Ensure that `Service#service_url` always returns a string
* Require Ruby 2.2 in gemspec

## 0.9.2

* Ignore connection options when connection object is passed in
* Don't send `Accept` header unless explicitly configured
* Use middleware for request/response logging
* Specifying an adapter is no longer necessary when passing a block to the constructor

## 0.9.1

* [New] Raising specific error classes instead of `RuntimeError` when request fails

## 0.9.0

* [Breaking] Use Faraday instead of Typhoeus as HTTP connection adapter.
* [Breaking] Deprecate `Service.open` in favor of using constructor directly.

## 0.8.2

* [Refactor] Moved `ComplexType` and `EnumType` class into `Schema`, respective property types into `Properties` namespace

## 0.8.1

* [New Feature] Basic support for `Collection` property type
* [Refactor] Moved all HTTP-related code into `Service::Request`,
             renamed `Query::Result` to `Service::Response`
* [Bugfix] Fixed incorrect `OData-Version` header being sent
* [Bugfix] Fixed duplicate namespace in Atom serialization

## 0.8.0

* [New Feature] Support for multiple schemas
* [Breaking] `Service#complex_types`, `Service#entity_types`,
  `Service#enum_types` and `Service#entity_sets` now return fully qualified
  type names
* [New Feature] Optional lenient property validation
* [Fixed] Incorrect URL representation for Decimal properties

## 0.7.0

Major rewrite

* Added support for OData 4.0
* Dropped support for OData 3.0

## 0.6.18

* Minor internal fixes to OData::Query::Criteria.

## 0.6.17

* Added more graceful handling of manually passed advanced queries to
  OData::Query::Criteria.

## 0.6.16

* Implemented OData::Query#empty? and fixed OData::Query#count.

## 0.6.15

* Fixed minor bug in last release.

## 0.6.14

* Changed implementation of OData::Association::Proxy#[] to properly handle
  empty associations.

## 0.6.13

* Minor bug fix in OData::Query::Result#each implementation.

## 0.6.12

* Minor bug fix in OData::Query::Result#each implementation.

## 0.6.11

* Added logic to allow OData::Query::Result#each to handle paginated results.

## 0.6.10

* Changed how associations behave with mulitiplicity of one.

## 0.6.9

* Changed how OData::Entity#from_xml functions to better work with feed results.

## 0.6.8

* Added empty checking when checking for a nil value.

## 0.6.7

* Changed how commit failures are handled to use logging instead of raising an
  error.
* Added errors array to OData::Entity.

## 0.6.6

* Updated OData::EntitySet#setup_entity_post_request to properly format primary
  key values when posting an entity.

## 0.6.5

* Fixed problem in OData::ComplexType#to_xml implementation.

## 0.6.4

* Added implementation of OData::ComplexType#type.

## 0.6.3

* Added OData::ComplexType#to_xml to make entity saving work correctly.

## 0.6.1

* Made a minor change to internals of OData::Query::Criteria.

## 0.6.0

* Added ability to handle associations in a reasonable way.

## 0.5.1-8

* Tons of changes throughout the code base

## 0.5.0

* Stopped using namespace from OData service as unique identifier in favor of
  a supplied name option when opening a service.

## 0.4.0

* Added OData::Query#execute to run query and return a result.
* Added OData::Query::Result to handle enumeration of query results.

## 0.3.2

* Refactored internals of the query interface.

## 0.3.1

* Resolved issues causing failure on Ruby 1.9 and JRuby.

## 0.3.0

* Removed dependency on ActiveSupport

## 0.2.0

* Added query interface for [System Query Options](http://www.odata.org/documentation/odata-version-3-0/odata-version-3-0-core-protocol#queryingcollections)
* Refactored internal uses of System Query Options

## 0.1.0

* Core read/write behavior for OData v1-3
