require 'logger'
require 'time'
require 'cgi'
require 'uri'
#require 'net/http'  #replaced with curb-fu for finer grain control
require 'base64'
require 'openssl'
require 'rexml/document'
require 'rexml/xpath'
require 'curb-fu'


module AwsSdb

  class Service
    def initialize(options={})
      @access_key_id = options[:access_key_id] || ENV['AMAZON_ACCESS_KEY_ID']
      @secret_access_key = options[:secret_access_key] || ENV['AMAZON_SECRET_ACCESS_KEY']
      @base_url = options[:url] || 'http://sdb.amazonaws.com'
      @logger = options[:logger] || Logger.new("aws_sdb.log")
    end
    
    def aws_esc(str)
      esc_str = CGI.escape(str)
      #plus to space
      esc_str1 = esc_str.gsub('%2B', '%20')
      #space to space
      #esc_str2 = esc_str.gsub('%2A', '*')
      #puts "ESCAPED FROM -> #{esc_str.inspect}  ->  #{esc_str1}"
      esc_str1
    end
    
    #def aws_unesc(str)
    #  unesc_str = str.gsub('%22',"\"")
    #end

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
    # <QueryWithAttributesResult><Item><Name>in-c2ffrw</Name><Attribute><Name>code</Name><Value>in-c2ffrw</Value></Attribute><Attribute><Name>date_created</Name><Value>2008-10-31</Value></Attribute></Item><Item>
    def query_with_attributes(domain, query, max = nil, token = nil)
      params = {
        'Action' => 'QueryWithAttributes',
        'QueryExpression' => query,
        'DomainName' => domain.to_s
      }
      params['NextToken'] =
        token unless token.nil? || token.empty?
      params['MaxNumberOfItems'] =
        max.to_s unless max.nil? || max.to_i == 0

      doc = call(:get, params)
      results = []
      REXML::XPath.each(doc, "//Item") do |item|
        name = REXML::XPath.first(item, './Name/text()').to_s


        attributes = {'Name' => name}
        REXML::XPath.each(item, "./Attribute") do |attr|
          key = REXML::XPath.first(attr, './Name/text()').to_s
          value = REXML::XPath.first(attr, './Value/text()').to_s
          ( attributes[key] ||= [] ) << value
        end
        results << attributes
      end
      return results, REXML::XPath.first(doc, '//NextToken/text()').to_s
    end

    # <QueryResult><ItemName>in-c2ffrw</ItemName><ItemName>in-72yagt</ItemName><ItemName>in-52j8gj</ItemName>
    def query(domain, query, max = nil, token = nil)
      esc_query = aws_esc(query)
      params = {
        'Action' => 'Select',
        'SelectExpression' => esc_query##, #CGI.escape(query),
        #'DomainName' => domain.to_s
      }
      params['NextToken'] =
        token unless token.nil? || token.empty?
      params['MaxNumberOfItems'] =
        max.to_s unless max.nil? || max.to_i == 0

      puts "QUERY EXPRESSION BEFORE CALL: #{esc_query.inspect}"
      doc = call(:get, params)
      results = []
      REXML::XPath.each(doc, '//ItemName/text()') do |item|
        results << item.to_s
      end

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
        ([]<<values).flatten.each do |value|
          params["Attribute.#{count}.Name"] = aws_esc(key.to_s) ###CGI.escape(key.to_s) ##key.to_s #CGI.escape(key.to_s)
          params["Attribute.#{count}.Value"] = aws_esc(value.to_s) ###CGI.escape(value.to_s) ##value.to_s #CGI.escape(value.to_s)
          params["Attribute.#{count}.Replace"] = replace
          count += 1
        end
      end
      call(:put, params)
      nil
    end

    #updated to support consitent read
    def get_attributes(domain, item, consist_read = 'true')
      doc = call(
        :get,
        {
          'Action' => 'GetAttributes',
          'DomainName' => domain.to_s,
          'ItemName' => item.to_s,
          'ConsistentRead' => 'true'
        }
      )
      attributes = {}
      REXML::XPath.each(doc, "//Attribute") do |attr|
        unesc_key = REXML::XPath.first(attr, './Name/text()').to_s
        unesc_value = REXML::XPath.first(attr, './Value/text()').to_s
        #unescape key and value to return to normal
        key = CGI.unescape(unesc_key)#aws_unesc(unesc_key) ###CGI.unescape(unesc_key) ##unesc_key #CGI.unescape(unesc_key)
        value = CGI.unescape(unesc_value)#aws_unesc(unesc_value) ###CGI.unescape(unesc_value) ##unesc_value #CGI.unescape(unesc_value)
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
      qs = []
      q_params.sort.each do |k,v|
        if k == "SelectExpression" 
          new_v = [k.to_s, v.to_s].join('=').gsub('+', '%20')
          puts "New V: #{new_v.inspect}"
          qs << new_v
        else
          qs << [CGI.escape(k.to_s), CGI.escape(v.to_s)].join('=')
        end
      end
      cq_string = qs.join('&')
    end

    def build_actual_query_string(q_params)
      qs = []
      q_params.sort.each do |k,v|
        if k == "SelectExpression" 
          qs << [k.to_s, v.to_s].join('=')
        else
          qs << [CGI.escape(k.to_s), CGI.escape(v.to_s)].join('=')
        end
      end
      aq_string = qs.join('&')
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
  


      
      puts "CALL: #{method} with #{params.inspect}"
      
  
      canonical_querystring = build_canonical_query_string(params)
      ##canonical_querystring = params.sort.collect { |k,v| [CGI.escape(k.to_s), CGI.escape(v.to_s)].join('=')}.join('&')
      ##canonical_querystring = params.sort.collect { |k,v| [k.to_s, v.to_s].join('=')}.join('&')
      ####canonical_querystring = params.sort.collect { |k,v| [aws_esc(k.to_s), aws_esc(v.to_s)].join('=')}.join('&')

      
      puts "CANONICAL: #{canonical_querystring.inspect}"
      
      string_to_sign= "GET\n#{URI.parse(@base_url).host}\n/\n#{canonical_querystring}"
      
      #sha256
      digest = OpenSSL::Digest::Digest.new('sha256')
      signature = Base64.encode64(OpenSSL::HMAC.digest(digest, @secret_access_key, string_to_sign)).chomp
      
      #sha1
      #digest = OpenSSL::Digest::Digest.new('sha256')
      #signature = Base64.encode64(OpenSSL::HMAC.digest(digest, @secret_access_key, string_to_sign)).chomp      
      
      params['Signature'] = signature
      puts "SIG: #{signature.inspect}"
      ###querystring = params.collect { |key, value| [CGI.escape(key.to_s), CGI.escape(value.to_s)].join('=') }.join('&') # order doesn't matter for the actual request
      ##querystring = params.collect { |key, value| [key.to_s, value.to_s].join('=') }.join('&') # order doesn't matter for the actual request
      ####querystring = params.sort.collect { |key, value| [aws_esc(key.to_s), aws_esc(value.to_s)].join('=') }.join('&') # order doesn't matter for the actual request
      querystring = build_actual_query_string(params)
      
      puts "ACTUALQUERY: #{querystring.inspect}"
      
      url = "#{@base_url}?#{querystring}"
      uri = URI.parse(url)

      #resp = CurbFu.get(url)
      
      resp_body =  `curl -X"GET" "#{url}" -A"simple ruby aws sdb wrapper"`
      
      puts "RESP: #{resp_body.inspect}"
      #puts "RESP: #{resp.body.inspect}"
 
      doc = REXML::Document.new(resp_body)
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
  end

end
