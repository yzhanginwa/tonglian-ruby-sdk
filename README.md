# tonglian-ruby-sdk
Ruby SDK for Tonglian Payment Gateway

## Installation
1. Put the following line into the Gemfile of your project
```
   gem 'tonglian-ruby-sdk'
```

2. Install the gems in Gemfile
```
   $ bundle install
```

## Usage
Initialize a TonglianRubySdk client instance
```
api_end_point = 'http://test.allinpay.com/op/gateway'
app_id = 'xxxxxxxxxxxxxxxx'
private_path = 'path-to-private-key-file'
private_password = 'password-to-decrypt-private-key-file'
public_path = 'path-to-tonglian-public-key-file'

client = TonglianRubySdk::Client.new(api_end_point, app_id, private_path, private_password, public_path)
```

Sent an API request to Tonglian gateway
```
method = 'allinpay.yunst.memberService.createMember'
params = {
  'bizUserId' => 'client-users-id-xxxxxx',
  "memberType" => 3,
  "source" => 1
}

client.request(method, params)
```
