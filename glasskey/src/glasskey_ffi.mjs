import {
  Option$None,
  Option$Some$0,
  Option$Some,
  Option$isSome,
} from "../gleam_stdlib/gleam/option.mjs";
import {
  AuthenticationCredential$AuthenticationCredential,
  Error$NotAllowed,
  Error$NotSupported,
  Error$UnknownError,
  RegistrationCredential$RegistrationCredential,
  authenticator_attachment_to_string as authenticatorAttachmentToString,
  classify_dom_exception as classifyDomException,
  requirement_to_string as requirementToString,
  transport_to_string as transportToString,
} from "./glasskey.mjs";
import {
  BitArray$BitArray,
  Result$Error,
  Result$Ok,
  toList,
} from "./gleam.mjs";

export function browserSupportsWebauthn() {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator !== "undefined" &&
    navigator.credentials != null
  );
}

export async function createCredential(opts) {
  const publicKey = {
    challenge: opts.challenge.rawBuffer,
    rp: opts.rp,
    user: {
      id: opts.user.id.rawBuffer,
      name: opts.user.name,
      displayName: opts.user.display_name,
    },
    pubKeyCredParams: [...opts.pub_key_cred_params].map((alg) => ({
      type: "public-key",
      alg,
    })),
  };

  const authenticatorSelection = buildAuthenticatorSelection(
    opts.authenticator_selection,
  );

  if (authenticatorSelection !== undefined) {
    publicKey.authenticatorSelection = authenticatorSelection;
  }

  if (Option$isSome(opts.timeout)) {
    publicKey.timeout = Option$Some$0(opts.timeout);
  }

  if (opts.exclude_credentials.length > 0) {
    publicKey.excludeCredentials = toCredentialDescriptors(
      opts.exclude_credentials,
    );
  }

  try {
    const credential = await navigator.credentials.create({ publicKey });
    if (!credential) {
      return Result$Error(Error$NotAllowed());
    }

    return Result$Ok(buildRegistrationCredential(credential));
  } catch (error) {
    return Result$Error(classifyJsError(error));
  }
}

function buildPublicKey(options) {
  const publicKey = {
    challenge: options.challenge.rawBuffer,
  };

  if (Option$isSome(options.user_verification)) {
    publicKey.userVerification = requirementToString(
      Option$Some$0(options.user_verification),
    );
  }

  if (Option$isSome(options.rp_id)) {
    publicKey.rpId = Option$Some$0(options.rp_id);
  }

  if (Option$isSome(options.timeout)) {
    publicKey.timeout = Option$Some$0(options.timeout);
  }

  if (options.allow_credentials.length > 0) {
    publicKey.allowCredentials = toCredentialDescriptors(
      options.allow_credentials,
    );
  }

  return publicKey;
}

export async function getCredential(opts) {
  const publicKey = buildPublicKey(opts);

  try {
    const credential = await navigator.credentials.get({ publicKey });
    if (!credential) {
      return Result$Error(Error$NotAllowed());
    }

    return Result$Ok(buildAuthenticationCredential(credential));
  } catch (error) {
    return Result$Error(classifyJsError(error));
  }
}

// Not async: must return the [promise, abort] tuple synchronously so the
// caller receives the abort handle before the ceremony resolves.
export function getConditionalCredential(opts) {
  const controller = new AbortController();
  const publicKey = buildPublicKey(opts);
  return [
    runConditionalGet(publicKey, controller.signal),
    () => controller.abort(),
  ];
}

async function runConditionalGet(publicKey, signal) {
  if (!(await isConditionalMediationAvailable())) {
    return Result$Error(Error$NotSupported());
  }

  try {
    const credential = await navigator.credentials.get({
      publicKey,
      mediation: "conditional",
      signal,
    });

    if (!credential) {
      return Result$Error(Error$NotAllowed());
    }

    return Result$Ok(buildAuthenticationCredential(credential));
  } catch (error) {
    return Result$Error(classifyJsError(error));
  }
}

function toBitArray(buffer) {
  return BitArray$BitArray(new Uint8Array(buffer));
}

function classifyJsError(error) {
  if (error instanceof DOMException) {
    return classifyDomException(error.name, describeError(error));
  }

  if (error instanceof Error) {
    return Error$UnknownError(describeError(error));
  }

  return Error$UnknownError(String(error));
}

function describeError(error) {
  if (error.cause === undefined || error.cause === null) {
    return error.message;
  }
  const cause =
    error.cause instanceof Error ? error.cause.message : String(error.cause);
  return error.message + " (cause: " + cause + ")";
}

function buildRegistrationCredential(credential) {
  const response = credential.response;
  const transports =
    typeof response.getTransports === "function"
      ? response.getTransports()
      : [];

  return RegistrationCredential$RegistrationCredential(
    credential.id,
    toBitArray(credential.rawId),
    toBitArray(response.clientDataJSON),
    toBitArray(response.attestationObject),
    toList(transports),
  );
}

function buildAuthenticationCredential(credential) {
  const response = credential.response;
  const userHandle = response.userHandle
    ? Option$Some(toBitArray(response.userHandle))
    : Option$None();

  return AuthenticationCredential$AuthenticationCredential(
    credential.id,
    toBitArray(credential.rawId),
    toBitArray(response.clientDataJSON),
    toBitArray(response.authenticatorData),
    toBitArray(response.signature),
    userHandle,
  );
}

function buildAuthenticatorSelection(selection) {
  if (!Option$isSome(selection)) {
    return undefined;
  }

  const inner = Option$Some$0(selection);
  const out = {};
  if (Option$isSome(inner.resident_key)) {
    out.residentKey = requirementToString(Option$Some$0(inner.resident_key));
  }

  if (Option$isSome(inner.user_verification)) {
    out.userVerification = requirementToString(
      Option$Some$0(inner.user_verification),
    );
  }

  if (Option$isSome(inner.authenticator_attachment)) {
    out.authenticatorAttachment = authenticatorAttachmentToString(
      Option$Some$0(inner.authenticator_attachment),
    );
  }

  return out;
}

function toCredentialDescriptors(descriptors) {
  return descriptors.map((d) => {
    const out = { type: "public-key", id: d.id.rawBuffer };
    const transports = [...d.transports].map(transportToString);
    if (transports.length > 0) {
      out.transports = transports;
    }
    return out;
  });
}

export async function platformAuthenticatorIsAvailable() {
  if (
    !browserSupportsWebauthn() ||
    typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !==
      "function"
  ) {
    return false;
  }
  return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}

export async function isConditionalMediationAvailable() {
  if (
    !browserSupportsWebauthn() ||
    typeof PublicKeyCredential.isConditionalMediationAvailable !== "function"
  ) {
    return false;
  }
  return PublicKeyCredential.isConditionalMediationAvailable();
}
