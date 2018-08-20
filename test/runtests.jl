using Test
import JSONWebTokens, SHA, MbedTLS,JSON
import Random.MersenneTwister
@testset "base64url_encode/decode" begin
    header = """{"alg":"HS256","typ":"JWT"}"""
    claims = """{"sub":"1234567890","name":"John Doe","iat":1516239022}"""
    secret = "123"
    header_and_claims_encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ=="
    @test JSONWebTokens.base64url_encode(header) * "." * JSONWebTokens.base64url_encode(claims) == header_and_claims_encoded
    @test JSONWebTokens.base64url_encode(SHA.hmac_sha2_256(Vector{UInt8}(secret), header_and_claims_encoded)) == "vljbOolpWXDUVXpKknxm1qzoAiyLMWSFGdzGJdbci28="
    encoding = JSONWebTokens.None()
    claims_dict = JSON.parse(claims)
    encoding2 = JSONWebTokens.HS256("secretkey")
    @show JSONWebTokens.encode(encoding2,claims)
    @test JSONWebTokens.decode(encoding, JSONWebTokens.encode(encoding, claims_dict)) == claims_dict
end

@testset "HS256 valid JSONWebTokens decode" begin
    jwt_encoded = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ==.kuy5U8zDsDQuthE0v7yyw8D9clMl4ZmTT/Qw0qiPmBI="
    encoding = JSONWebTokens.HS256("secretkey")
    claims_dict = JSONWebTokens.decode(encoding, jwt_encoded)
    @test claims_dict["sub"] == "1234567890"
    @test claims_dict["name"] == "John Doe"
    @test claims_dict["iat"] == 1516239022
end

@testset "HS256 invalid JSONWebTokens decode" begin
    encoding = JSONWebTokens.HS256("secretkey")
    jwt_encoded_invalid_1 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.8TLPbKjmE0uGLQyLnfHx2z-zy6G8qu5zFFXRSuJID_Y"
    @test_throws JSONWebTokens.InvalidSignatureError JSONWebTokens.decode(encoding, jwt_encoded_invalid_1)
end

@testset "HS256 encode/decode" begin
    encoding = JSONWebTokens.HS256("secretkey")
    claims_json = """{"sub":"1234567890","name":"John Doe","iat":1516239022}"""
    claims_dict = JSON.parse(claims_json)
    @test JSONWebTokens.encode(encoding, claims_json) == "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ==.kuy5U8zDsDQuthE0v7yyw8D9clMl4ZmTT/Qw0qiPmBI="
    @test JSONWebTokens.decode(encoding, JSONWebTokens.encode(encoding, claims_dict)) == claims_dict
end

# how to generate public/private key using openssl
# https://www.devco.net/archives/2006/02/13/public_-_private_key_encryption_using_openssl.php

# private.pem / public.pem generated using
# $ openssl genrsa -out private.pem 2048
# $ openssl rsa -in private.pem -out public.pem -outform PEM -pubout
# $ openssl genrsa -out private2.pem 2048
# $ openssl rsa -in private2.pem -out public2.pem -outform PEM -pubout

@testset "MbedTLS" begin
    header = """{"alg":"RS256","typ":"JWT"}"""
    claims = """{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}"""
    header_and_claims_encoded = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0="
    signature_encoded = "CzmFqSuWBB9LwFAzUNkPMcrEC0KLcetzOGOUW61MwDyd0jmhvpuV6xGmSXyUUC1XZ0muxuhrcQoo+25zEBRGuKTuYIQ2pppUN5ZLbxsQ6SpGzxrtUHzskV7+Lpg8zzy+w30nJvlgof70mB+HnfesWkISB2HPIwNCq05qV09KGOujew22SRQzTrsyYJOetVaRRB1i2hCblwSU7X0wHjDd7SFwQOdm/zwWwmAeCFWrwcLSuGIOFyuNjZ+s/jnTChTeo6gk65NHh8Ap2MRPe9xteAtFov/71/FM527rymqr3hD8I030yXPge5c8kKDC7Xd8BcLQFB3e/JAbNhw110U5tA=="
    @test JSONWebTokens.base64url_encode(header) * "." * JSONWebTokens.base64url_encode(claims) == header_and_claims_encoded

    private_key_file = "private.pem"
    @assert isfile(private_key_file) "Couldn't find test private key file $private_key_file."
    key = MbedTLS.parse_keyfile(private_key_file)
    _hash = MbedTLS.digest(MbedTLS.MD_SHA256, header_and_claims_encoded)
    output = MbedTLS.sign(key, MbedTLS.MD_SHA256, _hash, MersenneTwister(0))
    @test JSONWebTokens.base64url_encode(output) == signature_encoded

    public_key_file = "public.pem"
    @assert isfile(public_key_file) "Couldn't find test public key file $public_key_file."
    pubkey_string = read(open(public_key_file, "r"))
    pubkey = MbedTLS.PKContext()
    MbedTLS.parse_public_key!(pubkey, pubkey_string)
    @test MbedTLS.verify(pubkey, MbedTLS.MD_SHA256, _hash, JSONWebTokens.base64url_decode(signature_encoded)) == 0
end

@testset "RSA" begin
    fp_public = "public.pem"
    fp_private = "private.pem"
    @assert isfile(fp_public)
    @assert isfile(fp_private)
    rsa_public = JSONWebTokens.RS256(fp_public)
    rsa_private = JSONWebTokens.RS256(fp_private)

    claims = """{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}"""
    claims_dict = JSON.parse(claims)
    jwt = JSONWebTokens.encode(rsa_private, claims)
    @test startswith(jwt, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.")
    @test JSONWebTokens.decode(rsa_public, jwt) == claims_dict

    fp_public2 = "public2.pem"
    fp_private2 = "private2.pem"
    @assert isfile(fp_public2)
    @assert isfile(fp_private2)
    rsa_public2 = JSONWebTokens.RS256(fp_public2)
    rsa_private2 = JSONWebTokens.RS256(fp_private2)

    @test_throws JSONWebTokens.InvalidSignatureError JSONWebTokens.decode(rsa_public2, jwt)
    jwt2 = JSONWebTokens.encode(rsa_private2, claims_dict)
    @test jwt != jwt2
    @test JSONWebTokens.decode(rsa_public2, jwt2) == claims_dict
    @test_throws JSONWebTokens.InvalidSignatureError JSONWebTokens.decode(rsa_public, jwt2)

    @test_throws AssertionError JSONWebTokens.encode(rsa_public, claims_dict)
end
