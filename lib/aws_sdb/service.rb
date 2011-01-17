require 'logger'
require 'time'
require 'cgi'
require 'uri'
require 'base64'
require 'openssl'
require 'rexml/document'
require 'rexml/xpath'
require 'curb-fu'

#duck punch so that space converts to %20
class CGI
  @@accept_charset="UTF-8" unless defined?(@@accept_charset)

  def CGI::escape(string)
    string.gsub(/([^a-zA-Z0-9_.-]+)/n) do
      '%' + $1.unpack('H2' * $1.size).join('%').upcase
    end
  end
  
end

module AwsSdb

  class Service
    def initialize(options={})
      @access_key_id = options[:access_key_id] || ENV['AMAZON_ACCESS_KEY_ID']
      @secret_access_key = options[:secret_access_key] || ENV['AMAZON_SECRET_ACCESS_KEY']
      @base_url = options[:url] || 'http://sdb.amazonaws.com'
      @logger = options[:logger] || Logger.new("aws_sdb.log")
    end
    
    def list_domains(max = nil, token = nil)
      params = { 'Action' => 'ListDomains' }
      params['NextToken'] =
        token unless token.nil? || token.empty?
      params['MaxNumberOfDomains'] =
        max.to_s unless max.nil? || max.to_i == 0
      doc = call(:get, params)
      results = []
      REXML::XPath.each(doc, '//DomainName/text()') do |domain|
        results << domain.to_s
      end
      return results, REXML::XPath.first(doc, '//NextToken/text()').to_s
    end

    def create_domain(domain)
      domain.strip! if domain
      call(:post, { 'Action' => 'CreateDomain', 'DomainName'=> domain.to_s })
      nil
    end

    def delete_domain(domain)
      call(
        :delete,
        { 'Action' => 'DeleteDomain', 'DomainName' => domain.to_s }
      )
      nil
    end
     
    def select(query, max = nil, token = nil, consistent_read = 'true')
      query 
      params = {
        'Action' => 'Select',
        'SelectExpression' => query,
        'ConsistentRead' => consistent_read
      }
      params['NextToken'] =
        token unless token.nil? || token.empty?
      params['MaxNumberOfItems'] =
        max.to_s unless max.nil? || max.to_i == 0

      @logger.debug { "SELECT EXPRESSION BEFORE CALL: #{query.inspect}" } if @logger.debug?
      doc = call(:get, params)

      items = {}
      attributes = {}

      #build the result hash
      REXML::XPath.each(doc, '//Item') do |item_doc|
        item_name = item_doc.elements["Name"].text

        item_doc.each do |attrib_doc|
          att_name = attrib_doc.elements["Name"]
          att_value = attrib_doc.elements["Value"]
          
          next unless (att_name && att_value)
          
          attrib_name = CGI.unescape(att_name.text)
          attrib_value = CGI.unescape(att_value.text)

          add_value(attributes, attrib_name, attrib_value)
        end
        items[item_name] = attributes
        #reset attributes so we don't clobber next item
        attributes = {}
        items
      end
      results = items
      return results, REXML::XPath.first(doc, '//NextToken/text()').to_s
    end
    
    def put_attributes(domain, item, attributes, replace = true)
      params = {
        'Action' => 'PutAttributes',
        'DomainName' => domain.to_s,
        'ItemName' => item.to_s
      }
      count = 0
      #escaping key and value so signature computes correctly
      attributes.each do | key, values |
        ( []<<values ).flatten.each do |value|
          params["Attribute.#{count}.Name"] = CGI.escape(key.to_s)
          params["Attribute.#{count}.Value"] = CGI.escape(value.to_s)
          params["Attribute.#{count}.Replace"] = replace
          count += 1
        end
      end
      call(:put, params)
      nil
    end

    #updated to support consitent read
    def get_attributes(domain, item, consistent_read = 'true')
      doc = call(
        :get,
        {
          'Action' => 'GetAttributes',
          'DomainName' => domain.to_s,
          'ItemName' => item.to_s,
          'ConsistentRead' =>  consistent_read
        }
      )
      attributes = {}
      REXML::XPath.each(doc, "//Attribute") do |attr|
        unesc_key = REXML::XPath.first(attr, './Name/text()').to_s
        unesc_value = REXML::XPath.first(attr, './Value/text()').to_s
        #unescape key and value to return to normal
        key = CGI.unescape(unesc_key)
        value = CGI.unescape(unesc_value)
        ( attributes[key] ||= [] ) << value
      end
      attributes
    end

    def delete_attributes(domain, item)
      call(
        :delete,
        {
          'Action' => 'DeleteAttributes',
          'DomainName' => domain.to_s,
          'ItemName' => item.to_s
        }
      )
      nil
    end

    protected
    
    def build_canonical_query_string(q_params)
      q_params.sort.collect { |k,v| [CGI.escape(k.to_s), CGI.escape(v.to_s)].join('=')}.join('&')
    end

    def build_actual_query_string(q_params)
      q_params.sort.collect { |k,v| [CGI.escape(k.to_s), CGI.escape(v.to_s)].join('=')}.join('&')
    end

    def call(method, params)
      #updated to support signtature version 2
      params.merge!( {
          'Version' => '2009-04-15',
          'SignatureMethod' => 'HmacSHA256',
          #'SignatureMethod' => 'HmacSHA1',
          'SignatureVersion' => '2',
          'AWSAccessKeyId' => @access_key_id,
          'Timestamp' => Time.now.gmtime.iso8601
        }
      )
      @logger.debug { "CALL: #{method} with #{params.inspect}" } if @logger.debug?
      
      canonical_querystring = build_canonical_query_string(params)
      @logger.debug { "CANONICAL: #{canonical_querystring.inspect}" } if @logger.debug?
      
      string_to_sign= "GET\n#{URI.parse(@base_url).host}\n/\n#{canonical_querystring}"
      
      #sha256
      digest = OpenSSL::Digest::Digest.new('sha256')
      signature = Base64.encode64(OpenSSL::HMAC.digest(digest, @secret_access_key, string_to_sign)).chomp
      
      #sha1
      #digest = OpenSSL::Digest::Digest.new('sha256')
      #signature = Base64.encode64(OpenSSL::HMAC.digest(digest, @secret_access_key, string_to_sign)).chomp      
      
      params['Signature'] = signature
      querystring = build_actual_query_string(params)
      
      @logger.debug { "ACTUALQUERY: #{querystring.inspect}" } if @logger.debug?
      
      url = "#{@base_url}?#{querystring}"
      uri = URI.parse(url)

      resp = request(url)
      resp_body = resp.body
      
      @logger.debug { "RESP: #{resp_body.inspect}" } if @logger.debug?
 
      doc = REXML::Document.new(resp_body)
      
      @logger.debug { "DECODED DOC:" } if @logger.debug?
      
      error = doc.get_elements('*/Errors/Error')[0]
      
      raise(
        Module.class_eval(
          "AwsSdb::#{error.get_elements('Code')[0].text}Error"
        ).new(
          error.get_elements('Message')[0].text,
          doc.get_elements('*/RequestID')[0].text
        )
      ) unless error.nil?
      doc
    end
    
    #request with retries
    def request(url, retry_data={})
      resp = CurbFu.get(url) 
      if resp.nil? || resp.status == 503
        resp = retry_req(url, retry_data)
      end
      raise "No response!!" unless resp
      raise "No Body in Response" unless resp.body
      resp
    end
    
    private
    
    def retry_req(url, retry_data)
      resp = :retry
      #retry parameters
      max_retries = 10||retry_data[:max_retries]
      init_wait = 0.2||retry_data[:init_wait]
      wait_increase = 0.3||retry_data[:wait_increase]
      retry_data[:wait] = init_wait||retry_data[:wait]
      
      #wait a tiny bit before the first retry and reset retry data
      #then retry 
      1.upto(max_retries)  do |retry_att|
        sleep retry_data[:wait]
        #puts "RETRY: #{retry_att}, WAIT: #{retry_data[:wait]}"
        resp = request(url, retry_data)
        break if resp && resp.status && resp.status != 503 && resp.body
        retry_data[:wait] += wait_increase
        retry_data[:wait_increase] = wait_increase * retry_att #request back off
      end
      resp
    end
    
    def add_value(attributes, attrib_name, attrib_value)
      if attributes[attrib_name]
        attributes[attrib_name] << attrib_value
      else
        attributes[attrib_name] = [attrib_value]
      end
      attributes
    end

  end#class

end#module
