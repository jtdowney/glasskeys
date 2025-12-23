-module(test_crypto_ffi).

-export([sign_ecdsa_p256/2, load_keypair_from_pem/1]).

%% Sign a message using ES256 (ECDSA with P-256 and SHA-256)
%% Returns the signature in raw R||S format (64 bytes)
sign_ecdsa_p256(Message, PrivateKey) ->
    DerSig = crypto:sign(ecdsa, sha256, Message, [PrivateKey, secp256r1]),
    %% Convert DER signature to raw R||S format
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
    %% Take the last N bytes
    Skip = byte_size(Bin) - N,
    <<_:Skip/binary, Result:N/binary>> = Bin,
    Result.

%% Load a P-256 key pair from a PKCS#8 PEM file
%% Returns {PrivateKey, PublicKeyX, PublicKeyY}
load_keypair_from_pem(FilePath) ->
    {ok, PemBin} = file:read_file(FilePath),
    [PemEntry] = public_key:pem_decode(PemBin),
    ECPrivateKey = public_key:pem_entry_decode(PemEntry),
    PrivateKey = element(3, ECPrivateKey),
    PublicKeyUncompressed = element(5, ECPrivateKey),
    <<4, X:32/binary, Y:32/binary>> = PublicKeyUncompressed,
    {PrivateKey, X, Y}.
