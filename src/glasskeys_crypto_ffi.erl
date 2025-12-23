-module(glasskeys_crypto_ffi).
-export([crypto_verify_ecdsa_p256/3]).

crypto_verify_ecdsa_p256(Message, DerSignature, PublicKey) ->
    try
        crypto:verify(ecdsa, sha256, Message, DerSignature, [PublicKey, secp256r1])
    catch
        _:_ -> false
    end.
