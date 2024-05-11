# to avoid error when loading PKCS12 private key file
ENV['OPENSSL_CONF'] = './add-openssl-provider.conf'

require 'openssl'
require 'cgi'
require 'digest'
require 'base64'

module TonglianRubySdk
  class Signer
    def initialize(private_path, private_passwd, public_path)
      @private_path = private_path
      @private_passwd = private_passwd
      @public_path = public_path
    end

    def sign(params)
      str = make_sign_message(params)
      private_file = File.open(@private_path)
      private_key = OpenSSL::PKCS12.new(private_file, @private_passwd).key.export
      rsa = OpenSSL::PKey::RSA.new private_key
      rsa.sign('sha1', str.force_encoding('UTF-8'))
    end

    def verify?(params, sign)
      str = make_sign_message(params)
      public_file = File.open(@public_path)
      public_key = OpenSSL::X509::Certificate.new(public_file).public_key.export
      rsa = OpenSSL::PKey::RSA.new(public_key)
      rsa.verify('sha1', sign, str)
    end

    private

    def make_sign_message(params)
      sorted_params = []
      params.keys.sort.map do |k|
        next if %w[sign signType].include? k
        next if params[k].nil? || params[k].to_s.empty?

        sorted_params.push("#{k}=#{CGI.escape(params[k])}")
      end

      Base64.encode64(Digest::MD5.hexdigest(sorted_params.join('&')))
    end
  end
end
