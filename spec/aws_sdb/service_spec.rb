require File.dirname(__FILE__) + '/../spec_helper.rb'

require 'digest/sha1'
require 'net/http'
require 'rexml/document'

require 'rubygems'
require 'uuidtools'

include AwsSdb
=begin
describe Service, "when creating a new domain" do
  include UUIDTools
  
  before(:all) do
    @service = AwsSdb::Service.new
    @domain = "test-#{UUID.random_create.to_s}"
    domains = @service.list_domains[0]
    domains.each do |d|
      @service.delete_domain(d) if d =~ /^test/
    end
  end
  
  after(:all) do
    @service.delete_domain(@domain)
  end

  it "should not raise an error if a valid new domain name is given" do
    lambda {
      @service.create_domain("test-#{UUID.random_create.to_s}")
    }.should_not raise_error
  end

  it "should not raise an error if the domain name already exists" do
    domain = "test-#{UUID.random_create.to_s}"
    lambda {
      @service.create_domain(domain)
      @service.create_domain(domain)
    }.should_not raise_error
  end

  it "should raise an error if an a nil or '' domain name is given" do
    lambda {
      @service.create_domain('')
    }.should raise_error(InvalidParameterValueError)
    lambda {
      @service.create_domain(nil)
    }.should raise_error(InvalidParameterValueError)
    lambda {
      @service.create_domain('     ')
    }.should raise_error(InvalidParameterValueError)
  end

  it "should raise an error if the domain name length is < 3 or > 255" do
    lambda {
      @service.create_domain('xx')
    }.should raise_error(InvalidParameterValueError)
    lambda {
      @service.create_domain('x'*256)
    }.should raise_error(InvalidParameterValueError)
  end

  it "should only accept domain names with a-z, A-Z, 0-9, '_', '-', and '.' " do
    lambda {
      @service.create_domain('@$^*()')
    }.should raise_error(InvalidParameterValueError)
  end

  #it "should only accept a maximum of 100 domain names"

  #it "should not have to call amazon to determine domain name correctness"

end

describe Service, "when listing domains" do
  include UUIDTools
  
  before(:all) do
    @service = AwsSdb::Service.new
    @domain = "test-#{UUID.random_create.to_s}"
    @service.list_domains[0].each do |d|
      @service.delete_domain(d) if d =~ /^test/
    end
    @service.create_domain(@domain)
  end
  
  after(:all) do
    @service.delete_domain(@domain)
  end

  it "should return a complete list" do
    result = nil
    lambda { result = @service.list_domains[0] }.should_not raise_error
    result.should_not be_nil
    result.should_not be_empty
    result.include?(@domain).should == true
  end
end

describe Service, "when deleting domains" do
  include UUIDTools
  before(:all) do
    @service = AwsSdb::Service.new
    @domain = "test-#{UUID.random_create.to_s}"
    @service.list_domains[0].each do |d|
      @service.delete_domain(d) if d =~ /^test/
    end
    @service.create_domain(@domain)
  end
  
  before(:each) do
    #sleep 0.2
  end

  after do
    @service.delete_domain(@domain)
  end

  it "should be able to delete an existing domain" do
    lambda { @service.delete_domain(@domain) }.should_not raise_error
  end

  it "should not raise an error trying to delete a non-existing domain" do
    lambda {
      @service.delete_domain(UUID.random_create.to_s)
    }.should_not raise_error
  end
end
=end
describe Service, "when managing items" do
    include UUIDTools
    
  before(:all) do
    @service = AwsSdb::Service.new
    @domain = "test-#{UUID.random_create.to_s}"
    @service.list_domains[0].each do |d|
      @service.delete_domain(d) if d =~ /^test/
    end
    @service.create_domain(@domain)
    @item = "test-#{UUID.random_create.to_s}"
    @attributes = {
      :question => 'What is the answer?',
      :answer => [ true, 'testing123', 4.2, 42, 420 ]
    }
  end

  after(:all) do
     @service.delete_domain(@domain)
  end

  it "should be able to put attributes" do
    lambda {
      @service.put_attributes(@domain, @item, @attributes)
    }.should_not raise_error
  end

  it "should be able to get attributes" do
    result = nil
    lambda {
      result = @service.get_attributes(@domain, @item)
    }.should_not raise_error
    result.should_not be_nil
    result.should_not be_empty
    result.has_key?('answer').should == true
    @attributes[:answer].each do |v|
      result['answer'].include?(v.to_s).should == true
    end
  end

  it "should be able to select all from domain" do
    #add another set of data
    item2 = "test-#{UUID.random_create.to_s}"
    attributes2 = {
      :question => "What are your favorite colors?",
      :favorite_colors => ['red', 'green', 'blue'],
      :answer => 'blue'
      }
      
    @service.put_attributes(@domain, item2, attributes2)
      
    query_str = "select * from `#{@domain}`"
    result = nil
    #lambda {
      result = @service.select(query_str)
    #}.should_not raise_error
    result.should_not be_nil
    result.should_not be_empty
    result.should_not be_nil
    result[0].keys.include?(@item).should == true
    result[0].values.size.should == 2
    #attribute names
    result[0].values[0].keys.sort.should == ['answer', 'question']
    #questions
    result[0].values[0]['question'].should == ['What is the answer?']
    #answers
    result[0].values[0]['answer'].size == 5
    result[0].values[0]['answer'].include?("42").should == true
    result[0].values[0]['answer'].include?("testing123").should == true
    #attribute names
    result[0].values[1].keys.sort.should == ['answer', 'favorite_colors', 'question']
    #questions
    result[0].values[1]['question'].should == ['What are your favorite colors?']
    #answers
    result[0].values[1]['favorite_colors'].size == 3
    result[0].values[1]['favorite_colors'].sort.should == ['blue', 'green', 'red']
    result[0].values[1]['answer'].should == ['blue']
  end


  it "should be able to delete attributes" do
    lambda {
      @service.delete_attributes(@domain, @item)
    }.should_not raise_error
  end
end

# TODO Pull the specs from the amazon docs and write more rspec
# 100 attributes per each call
# 256 total attribute name-value pairs per item
# 250 million attributes per domain
# 10 GB of total user data storage per domain
# ...etc...
