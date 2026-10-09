// Minimal WebAuthn helpers (py_webauthn JSON options <-> browser credential API).

const b64urlToBuf = (s: string): ArrayBuffer => {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
};

const bufToB64url = (buf: ArrayBuffer | null): string | null => {
  if (!buf) return null;
  let bin = "";
  new Uint8Array(buf).forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

/* eslint-disable @typescript-eslint/no-explicit-any */
export async function createCredential(options: any): Promise<Record<string, unknown>> {
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    user: { ...options.user, id: b64urlToBuf(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c: any) => ({ ...c, id: b64urlToBuf(c.id) })),
  };
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential;
  const resp = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(resp.clientDataJSON),
      attestationObject: bufToB64url(resp.attestationObject),
      transports: resp.getTransports?.() ?? [],
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}

export async function getAssertion(options: any): Promise<Record<string, unknown>> {
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c: any) => ({ ...c, id: b64urlToBuf(c.id) })),
  };
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential;
  const resp = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(resp.clientDataJSON),
      authenticatorData: bufToB64url(resp.authenticatorData),
      signature: bufToB64url(resp.signature),
      userHandle: bufToB64url(resp.userHandle),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  };
}
