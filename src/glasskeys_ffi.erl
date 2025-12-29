-module(glasskeys_ffi).

-export([verify_ecdsa_p256/3, generate_keypair/0, sign_ecdsa_p256/2]).

%% Verify an ECDSA P-256 signature
%% Returns true if valid, false otherwise
verify_ecdsa_p256(Message, DerSignature, PublicKey) ->
    try
        crypto:verify(ecdsa, sha256, Message, DerSignature, [PublicKey, secp256r1])
    catch
        _:_ -> false
    end.

%% Generate a random P-256 key pair
%% Returns {PrivateKey, X, Y} where X and Y are the public point coordinates
generate_keypair() ->
    {PublicKey, PrivateKey} = crypto:generate_key(ecdh, secp256r1),
    <<4, X:32/binary, Y:32/binary>> = PublicKey,
    {PrivateKey, X, Y}.

%% Sign a message using ES256 (ECDSA with P-256 and SHA-256)
%% Returns the signature in raw R||S format (64 bytes)
sign_ecdsa_p256(Message, PrivateKey) ->
    DerSig = crypto:sign(ecdsa, sha256, Message, [PrivateKey, secp256r1]),
    der_to_raw(DerSig).

%% Convert DER-encoded signature to raw R||S format
der_to_raw(<<16#30,
             _Len,
             16#02,
             RLen,
             RBytes:RLen/binary,
             16#02,
             SLen,
             SBytes:SLen/binary>>) ->
    R = pad_or_trim(RBytes, 32),
    S = pad_or_trim(SBytes, 32),
    <<R/binary, S/binary>>.

%% Pad with leading zeros or trim leading zeros to get exactly N bytes
pad_or_trim(Bin, N) when byte_size(Bin) == N ->
    Bin;
pad_or_trim(Bin, N) when byte_size(Bin) < N ->
    Padding = N - byte_size(Bin),
    <<0:(Padding * 8), Bin/binary>>;
pad_or_trim(<<0, Rest/binary>>, N) when byte_size(Rest) >= N ->
    pad_or_trim(Rest, N);
pad_or_trim(Bin, N) when byte_size(Bin) > N ->
    Skip = byte_size(Bin) - N,
    <<_:Skip/binary, Result:N/binary>> = Bin,
    Result.
