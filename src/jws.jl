
base64url_encode(s) = Base64.base64encode(s)

function base64url_decode(s::AbstractString)
    return Base64.base64decode(s)
end

find_dots(str::AbstractString) = findall(x -> x == '.', str)

function jws_split(str::AbstractString)
    dot_indexes = find_dots(str)

    if isempty(dot_indexes)
        throw(MalformedJWTError("JWT must contain at least one '.' character."))
    elseif length(dot_indexes) > 2
        throw(NotSupportedJWTError("JWE format is not supported. Only JWS is supported for now."))
    end

    header = SubString(str, 1, dot_indexes[1] - 1)

    if length(dot_indexes) == 1
        claims = SubString(str, dot_indexes[1] + 1, length(str))
        signature = ""
    else
        claims = SubString(str, dot_indexes[1] + 1, dot_indexes[2] - 1)
        signature = SubString(str, dot_indexes[2] + 1, length(str))
    end

    return header, claims, signature
end

function jws_header_dict(header_encoded::AbstractString)
    try
        header_dict = JSON.parse(String(base64url_decode(header_encoded)))
        @assert haskey(header_dict, "alg") "\"alg\" attribute is missing."
        @assert haskey(header_dict, "typ") "\"typ\" attribute is missing."
        @assert header_dict["typ"] == "JWT" "Expected \"typ\" == \"JWT\". Found $(header_dict["typ"])."
        return header_dict
    catch e
        throw(MalformedJWTError("Couldn't parse header ($e)."))
    end
end

function jws_claims_dict(claims_encoded::AbstractString)
    try
        claims_dict = JSON.parse(String(base64url_decode(claims_encoded)))
        return claims_dict
    catch e
        throw(MalformedJWTError("Couldn't parse claims ($e)."))
    end
end

function decode(encoding::Encoding, str::AbstractString)
    header_encoded, claims_encoded, signature_encoded = jws_split(str)
    header_dict = jws_header_dict(header_encoded)

    if isempty(signature_encoded)
        throw(MalformedJWTError("Expected alg $(alg(encoding)), but found empty signature field."))
    end

    if header_dict["alg"] != alg(encoding)
        throw(MalformedJWTError("Expected alg $(alg(encoding)). Found $(header_dict["alg"])."))
    end

    verify(encoding, str)
    return jws_claims_dict(claims_encoded)
end

function has_valid_signature(encoding::Encoding, str::AbstractString) :: Bool
    last_dot_index = findlast( x -> x == '.', str)
    if last_dot_index == 0
        throw(MalformedJWTError("JWT must contain at least one '.' character."))
    end
    header_and_claims_encoded = SubString(str, 1, last_dot_index - 1)

    if length(str) <= last_dot_index + 1
       throw(MalformedJWTError("JWT has no signature."))
    end

    signature_encoded = SubString(str, last_dot_index + 1, length(str))
    return has_valid_signature(encoding, header_and_claims_encoded, signature_encoded)
end

verify(encoding::Encoding, str::AbstractString) = !has_valid_signature(encoding, str) && throw(InvalidSignatureError())
encode(encoding::Encoding, claims_dict::Dict{S, A}) where {S<:AbstractString, A} = encode(encoding, JSON.json(claims_dict))

function encode(encoding::Encoding, claims_json::AbstractString)
    header_encoded = base64url_encode("""{"alg":"$(alg(encoding))","typ":"JWT"}""")
    claims_encoded = base64url_encode(claims_json)
    header_and_claims_encoded = header_encoded * "." * claims_encoded
    signature = sign(encoding, header_and_claims_encoded)
    return header_and_claims_encoded * "." * signature
end
