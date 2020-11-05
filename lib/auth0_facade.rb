require 'net/http'
require 'securerandom'
require 'json'
module Nextia
    module Implementations
        module Auth0
            class Auth0Facade
                def initialize(config)
                    @config = config
                end
                def create_user(email, first_name, last_name,  password="A#{SecureRandom.hex(15)}")
                    request_body_json = {
                        "email" => email,
                        "password" => password,
                        "verify_email" => true,
                        "given_name" => first_name,
                        "family_name" => last_name,
                        "connection" => @config[:CONNECTION]
                    }.to_json

                    headers = {
                        'Authorization' => "Bearer #{access_token}",
                        'Content-Type' => 'application/json'
                    }

                    register_user_uri = URI.parse("#{@config[:MACHINE_APP_AUDIENCE]}/users")
                    register_user_request = Net::HTTP.new(register_user_uri.host, register_user_uri.port)
                    register_user_request.use_ssl = true

                    request_config = Net::HTTP::Post.new(register_user_uri.path, initheader = headers)
                    request_config.body = "#{request_body_json}"
                    response = register_user_request.request(request_config)
                    
                    raise("Error. #{JSON.parse(response.body)["message"]}") if response.code.to_s != "201"
                    return JSON.parse(response.body)["user_id"]
                end

                private
                def access_token
                    uri = URI("#{@config[:DOMAIN]}/oauth/token")

                    body = { 
                        "grant_type" => "client_credentials",
                        "client_id" => @config[:MACHINE_APP_CLIENT_ID],
                        "client_secret" => @config[:MACHINE_APP_CLIENT_SECRET],
                        "scope" => "update:users",
                        "audience" =>  "#{@config[:MACHINE_APP_AUDIENCE]}/"
                    }
                    response = Net::HTTP.post_form(uri, body)
                    JSON.parse(response.body)["access_token"]
                end
            end
        end
    end
end