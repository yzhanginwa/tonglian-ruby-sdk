# to avoid error when loading PKCS12 private key file
current_dir = File.dirname(__FILE__)
provider_conf = File.join(current_dir, 'add-openssl-provider.conf')
ENV['OPENSSL_CONF'] ||= provider_conf

require 'openssl'
require 'cgi'
require 'digest'
require 'base64'
require 'net/http'
require 'active_support/all'

module TonglianRubySdk
  # Client class to handle request and responses to and from Tonglian gateway
  class Client
    REQUEST_STUB = {
      'charset'  => 'utf-8',
      'format'   => 'JSON',
      'signType' => 'SHA256WithRSA',
      'version'  => '1.0'
    }.freeze

    def initialize(api_end_point, app_id, private_path, private_passwd, public_path)
      @api_end_point = api_end_point
      @app_id = app_id
      @signer = Signer.new(private_path, private_passwd, public_path)
    end

    def request(method, params)
      data = REQUEST_STUB.dup
      data['appId']      = @app_id
      data['method']     = method
      data['timestamp']  = timestamp
      data['bizContent'] = params.to_json
      data['sign']       = @signer.sign(data)

      url = URI(@api_end_point)
      http = Net::HTTP.new(url.host, url.port)
      http.use_ssl = true if @api_end_point.downcase.starts_with?('https') # Enable SSL for HTTPS

      request = Net::HTTP::Post.new(url.request_uri)
      request['Content-Type'] = 'application/x-www-form-urlencoded'
      request.body = URI.encode_www_form(data)
      response = http.request(request)

      object = JSON.parse(response.body)
      @signer.verify?(object) || raise('Invalid response signature!')
      { 'code' => response.code, 'data' => object }
    end

    private

    def timestamp
      timezone = ActiveSupport::TimeZone.new('Asia/Shanghai')
      current_time = Time.now.in_time_zone(timezone)
      current_time.strftime('%Y-%m-%d %H:%M:%S')
    end
  end

  # To sign client request message and verify tonglian's response message
  class Signer
    def initialize(private_path, private_passwd, public_path)
      @private_path = private_path
      @private_passwd = private_passwd
      @public_path = public_path
    end

    def sign(params)
      message = make_sign_message(params)
      rsa = OpenSSL::PKey::RSA.new private_key
      Base64.strict_encode64(rsa.sign(OpenSSL::Digest.new('SHA256'), message))
    end

    def verify?(params, signature = nil)
      signature = params['sign'] if signature.nil? || signature.to_s.empty?
      params.delete('sign')
      message = make_verify_message(params)

      public_file = File.open(@public_path)
      public_key = OpenSSL::X509::Certificate.new(public_file).public_key.export
      rsa = OpenSSL::PKey::RSA.new(public_key)
      rsa.verify(OpenSSL::Digest.new('SHA256'), Base64.decode64(signature), message)
    end

    private

    def private_key
      return @private_key if @private_key
      private_file = File.open(@private_path)
      @private_key = OpenSSL::PKCS12.new(private_file, @private_passwd).key.export
    end

    def public_key
      return @public_key if @public_key

      public_file = File.open(@public_path)
      @public_key = OpenSSL::X509::Certificate.new(public_file).public_key.export
    end

    def make_sign_message(params)
      sorted_params = []
      params.keys.sort.map do |k|
        next if %w[sign signType].include? k
        next if params[k].nil? || params[k].to_s.empty?

        sorted_params.push("#{k}=#{params[k]}")
      end

      flattened_params = sorted_params.join('&')
      md5_digest = Digest::MD5.digest(flattened_params)
      Base64.strict_encode64(md5_digest)
    end

    def make_verify_message(params)
      params = sort_object(params)
      flattened_params = params.to_json
      Base64.strict_encode64(Digest::MD5.digest(flattened_params))
    end

    # In Ruby 3, a hash preserves the order the keys are inserted
    # So we can make a 'sorted' hash and generate a sorted json later
    def sort_object(obj)
      result = nil
      if obj.is_a? Hash
        result = {}
        obj.keys.sort.each { |k| result[k] = sort_object(obj[k]) }
      elsif obj.is_a? Array
        # If obj is array, it doesn't need to sort.
        # But still need to sort the items if they're hashes.
        # And this process should recursively go to the bottom
        result = []
        obj.each { |i| result.push(sort_object(i)) }
      else
        result = obj
      end
      result
    end
  end
end
