import {
  BitArray$BitArray,
  Result$Ok,
  Result$Error,
  toList,
} from "./gleam.mjs";
import {
  Option$Some,
  Option$None,
  Option$isSome,
  Option$Some$0,
} from "../gleam_stdlib/gleam/option.mjs";
import {
  CreateSnapshot$CreateSnapshot,
  GetSnapshot$GetSnapshot,
} from "./support/helpers.mjs";

class FakeDOMException extends Error {
  constructor(message, name) {
    super(message);
    this.name = name;
  }
}

let originalState = null;
let lastCreateOptions = null;
let lastGetOptions = null;
let lastGetSignal = null;
let createBehavior = { kind: "credential", value: null };
let getBehavior = { kind: "credential", value: null };
let conditionalMediationAvailable = true;
let platformAuthenticatorAvailable = true;

function snapshotGlobal(key) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, key);
  return { present: descriptor !== undefined, descriptor };
}

function restoreGlobal(key, snap) {
  if (snap.present) {
    Object.defineProperty(globalThis, key, snap.descriptor);
  } else {
    delete globalThis[key];
  }
}

function setGlobal(key, value) {
  Object.defineProperty(globalThis, key, {
    value,
    configurable: true,
    writable: true,
    enumerable: false,
  });
}

function runBehavior(behavior) {
  switch (behavior.kind) {
    case "null":
      return null;
    case "credential":
      return behavior.value;
    case "throw":
      throw behavior.error;
    default:
      throw new Error("unknown behavior: " + behavior.kind);
  }
}

function makeFakeCredentials() {
  return {
    async create(options) {
      lastCreateOptions = options.publicKey;
      return runBehavior(createBehavior);
    },
    async get(options) {
      lastGetOptions = options.publicKey;
      lastGetSignal = options.signal ?? null;
      return runBehavior(getBehavior);
    },
  };
}

export function installFakeNavigator() {
  uninstallFakeNavigator();
  originalState = {
    window: snapshotGlobal("window"),
    navigator: snapshotGlobal("navigator"),
    PublicKeyCredential: snapshotGlobal("PublicKeyCredential"),
    DOMException: snapshotGlobal("DOMException"),
  };

  lastCreateOptions = null;
  lastGetOptions = null;
  lastGetSignal = null;
  createBehavior = { kind: "credential", value: null };
  getBehavior = { kind: "credential", value: null };
  conditionalMediationAvailable = true;
  platformAuthenticatorAvailable = true;

  class FakePublicKeyCredential {
    static async isConditionalMediationAvailable() {
      return conditionalMediationAvailable;
    }
    static async isUserVerifyingPlatformAuthenticatorAvailable() {
      return platformAuthenticatorAvailable;
    }
  }

  setGlobal("window", { PublicKeyCredential: FakePublicKeyCredential });
  setGlobal("PublicKeyCredential", FakePublicKeyCredential);
  setGlobal("DOMException", FakeDOMException);
  setGlobal("navigator", { credentials: makeFakeCredentials() });
}

export function installFakeNavigatorMinimal() {
  uninstallFakeNavigator();
  originalState = {
    window: snapshotGlobal("window"),
    navigator: snapshotGlobal("navigator"),
    PublicKeyCredential: snapshotGlobal("PublicKeyCredential"),
    DOMException: snapshotGlobal("DOMException"),
  };

  class MinimalFakePublicKeyCredential {}

  setGlobal("window", { PublicKeyCredential: MinimalFakePublicKeyCredential });
  setGlobal("PublicKeyCredential", MinimalFakePublicKeyCredential);
  setGlobal("DOMException", FakeDOMException);
  setGlobal("navigator", { credentials: makeFakeCredentials() });
}

export function uninstallFakeNavigator() {
  if (originalState === null) return;
  restoreGlobal("window", originalState.window);
  restoreGlobal("navigator", originalState.navigator);
  restoreGlobal("PublicKeyCredential", originalState.PublicKeyCredential);
  restoreGlobal("DOMException", originalState.DOMException);
  originalState = null;
  lastCreateOptions = null;
  lastGetOptions = null;
  lastGetSignal = null;
}

export function setCreateCredential(rawId, clientDataJson, attestationObject) {
  setCreateCredentialWithTransports(
    rawId,
    clientDataJson,
    attestationObject,
    toList([]),
  );
}

export function setCreateCredentialWithTransports(
  rawId,
  clientDataJson,
  attestationObject,
  transports,
) {
  const transportArray = [...transports];
  createBehavior = {
    kind: "credential",
    value: {
      id: "fixture-cred-id",
      rawId: rawId.rawBuffer.buffer,
      response: {
        clientDataJSON: clientDataJson.rawBuffer.buffer,
        attestationObject: attestationObject.rawBuffer.buffer,
        getTransports: () => [...transportArray],
      },
    },
  };
}

export function setCreateNull() {
  createBehavior = { kind: "null" };
}

export function setCreateDomException(name, message) {
  createBehavior = {
    kind: "throw",
    error: new FakeDOMException(message, name),
  };
}

export function setCreatePlainError(message) {
  createBehavior = { kind: "throw", error: new Error(message) };
}

export function setGetCredential(
  rawId,
  clientDataJson,
  authenticatorData,
  signature,
  userHandle,
) {
  const response = {
    clientDataJSON: clientDataJson.rawBuffer.buffer,
    authenticatorData: authenticatorData.rawBuffer.buffer,
    signature: signature.rawBuffer.buffer,
  };
  if (Option$isSome(userHandle)) {
    response.userHandle = Option$Some$0(userHandle).rawBuffer.buffer;
  }
  getBehavior = {
    kind: "credential",
    value: {
      id: "fixture-assert-id",
      rawId: rawId.rawBuffer.buffer,
      response,
    },
  };
}

export function setGetNull() {
  getBehavior = { kind: "null" };
}

export function setGetDomException(name, message) {
  getBehavior = {
    kind: "throw",
    error: new FakeDOMException(message, name),
  };
}

export function setGetPlainError(message) {
  getBehavior = { kind: "throw", error: new Error(message) };
}

export function setConditionalMediationAvailable(available) {
  conditionalMediationAvailable = available;
}

export function setPlatformAuthenticatorAvailable(available) {
  platformAuthenticatorAvailable = available;
}

function challengeBitArray(value) {
  if (value instanceof ArrayBuffer)
    return BitArray$BitArray(new Uint8Array(value));
  if (ArrayBuffer.isView(value))
    return BitArray$BitArray(new Uint8Array(value.buffer));
  throw new Error("fake navigator: challenge was not a buffer");
}

function optionalString(value) {
  return typeof value === "string" ? Option$Some(value) : Option$None();
}

function optionalNumber(value) {
  return typeof value === "number" ? Option$Some(value) : Option$None();
}

function descriptorTransportsList(descriptors) {
  return toList(
    (descriptors ?? []).map((d) => toList([...(d.transports ?? [])])),
  );
}

export function lastCreateSnapshot() {
  if (lastCreateOptions === null) return Result$Error(undefined);
  const pk = lastCreateOptions;
  return Result$Ok(
    CreateSnapshot$CreateSnapshot(
      challengeBitArray(pk.challenge),
      pk.rp.id,
      optionalNumber(pk.timeout),
      optionalString(pk.authenticatorSelection?.authenticatorAttachment),
      pk.excludeCredentials?.length ?? 0,
      descriptorTransportsList(pk.excludeCredentials),
      optionalString(pk.authenticatorSelection?.residentKey),
      optionalString(pk.authenticatorSelection?.userVerification),
      pk.authenticatorSelection !== undefined,
      toList(pk.pubKeyCredParams.map((p) => p.alg)),
    ),
  );
}

export function lastGetSnapshot() {
  if (lastGetOptions === null) return Result$Error(undefined);
  const pk = lastGetOptions;
  return Result$Ok(
    GetSnapshot$GetSnapshot(
      optionalString(pk.rpId),
      optionalNumber(pk.timeout),
      optionalString(pk.userVerification),
      pk.allowCredentials?.length ?? 0,
      descriptorTransportsList(pk.allowCredentials),
    ),
  );
}

export function lastGetSignalAborted() {
  if (lastGetSignal === null) return Result$Error(undefined);
  return Result$Ok(lastGetSignal.aborted === true);
}
