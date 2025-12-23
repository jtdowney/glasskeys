if (checkWebAuthn()) {
  document.getElementById('passkey-btn').addEventListener('click', async () => {
    const statusEl = document.getElementById('status');
    const btn = document.getElementById('passkey-btn');

    try {
      btn.setAttribute('aria-busy', 'true');
      statusEl.textContent = 'Requesting challenge...';

      const beginRes = await fetch('/api/login/begin', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      if (!beginRes.ok) {
        const err = await beginRes.json();
        throw new Error(err.error || 'Login failed');
      }

      const options = await beginRes.json();

      const publicKeyOptions = {
        challenge: base64UrlDecode(options.publicKey.challenge),
        rpId: options.publicKey.rpId,
        timeout: options.publicKey.timeout,
        userVerification: options.publicKey.userVerification,
      };

      statusEl.textContent = 'Select your passkey...';
      const credential = await navigator.credentials.get({
        publicKey: publicKeyOptions,
      });

      statusEl.textContent = 'Verifying...';

      const completeRes = await fetch('/api/login/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: options.session_id,
          credential: {
            id: base64UrlEncode(credential.rawId),
            rawId: base64UrlEncode(credential.rawId),
            type: credential.type,
            response: {
              authenticatorData: base64UrlEncode(credential.response.authenticatorData),
              clientDataJSON: base64UrlEncode(credential.response.clientDataJSON),
              signature: base64UrlEncode(credential.response.signature),
              userHandle: credential.response.userHandle
                ? base64UrlEncode(credential.response.userHandle)
                : null,
            },
          },
        }),
      });

      if (!completeRes.ok) {
        const err = await completeRes.json();
        throw new Error(err.error || 'Login failed');
      }

      window.location.href = '/welcome';

    } catch (err) {
      statusEl.textContent = 'Error: ' + err.message;
      console.error('Login error:', err);
    } finally {
      btn.removeAttribute('aria-busy');
    }
  });
}
