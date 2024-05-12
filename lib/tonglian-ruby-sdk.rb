# to avoid error when loading PKCS12 private key file
ENV['OPENSSL_CONF'] = './add-openssl-provider.conf'

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

      # Handle response
      puts response.code
      puts response.body
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
      str = make_sign_message(params)
      rsa = OpenSSL::PKey::RSA.new private_key
      Base64.strict_encode64(rsa.sign('sha1', str.force_encoding('UTF-8')))
    end

    def verify?(params, signature = nil)
      signature = params['sign'] if signature.nil? || signature.to_s.empty?
      str = make_sign_message(params)
      public_file = File.open(@public_path)
      public_key = OpenSSL::X509::Certificate.new(public_file).public_key.export
      rsa = OpenSSL::PKey::RSA.new(public_key)
      rsa.verify('sha1', Base64.decode64(signature), str)
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
        #sorted_params.push("#{k}=#{CGI.escape(params[k])}")
        sorted_params.push("#{k}=#{params[k]}")
      end

      Base64.strict_encode64(Digest::MD5.hexdigest(sorted_params.join('&')))
    end
  end
end
