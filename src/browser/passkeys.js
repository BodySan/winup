// Adapted from KeePassXC-Browser, GPL-3.0. See licenses/KeePassXC-Browser.txt.
'use strict';

(async () => {
    const PASSKEYS_NO_LOGINS_FOUND = 15;
    const PASSKEYS_ATTESTATION_NOT_SUPPORTED = 20;
    const PASSKEYS_CREDENTIAL_IS_EXCLUDED = 21;
    const PASSKEYS_REQUEST_CANCELED = 22;
    const PASSKEYS_INVALID_USER_VERIFICATION = 23;
    const PASSKEYS_EMPTY_PUBLIC_KEY = 24;
    const PASSKEYS_INVALID_URL_PROVIDED = 25;
    const PASSKEYS_ORIGIN_NOT_ALLOWED = 26;
    const PASSKEYS_DOMAIN_IS_NOT_VALID = 27;
    const PASSKEYS_DOMAIN_RPID_MISMATCH = 28;
    const PASSKEYS_NO_SUPPORTED_ALGORITHMS = 29;
    const PASSKEYS_WAIT_FOR_LIFETIMER = 30;
    const PASSKEYS_UNKNOWN_ERROR = 31;
    const PASSKEYS_INVALID_CHALLENGE = 32;
    const PASSKEYS_INVALID_USER_ID = 33;
    const PASSKEYS_EVAL_BY_CREDENTIAL_NOT_SUPPORTED = 34;
    const PASSKEYS_EVAL_BY_CREDENTIAL_NOT_EMPTY = 35;
    const PASSKEYS_EVAL_BY_CREDENTIAL_NOT_FOUND = 36;

    const winupStringToArrayBuffer = function(str) {
        const arr = Uint8Array.from(str, c => c.charCodeAt(0));
        return arr.buffer;
    };

    // From URL encoded base64 string to ArrayBuffer
    const winupBase64ToArrayBuffer = function(str) {
        return winupStringToArrayBuffer(window.atob(str?.replaceAll('-', '+').replaceAll('_', '/')));
    };

    // From ArrayBuffer to URL encoded base64 string
    const winupArrayBufferToBase64 = function(buf) {
        const str = [ ...new Uint8Array(buf) ].map(c => String.fromCharCode(c)).join('');
        return window.btoa(str).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    };

    // Returns the PublicKeyCredential as JSON
    // See: https://w3c.github.io/webauthn/#dom-publickeycredential-tojson
    const winupPublicKeyCredentialJson = function (credential, publicKey) {
        const clientExtensionResults = credential.getClientExtensionResults();
        const type = credential.type;
        const authenticatorAttachment = credential.authenticatorAttachment;
        let response;

        if (credential.response instanceof AuthenticatorAttestationResponse) {
            const responsePublicKey = credential.response.getPublicKey();
            response = {
                clientDataJSON: publicKey.response.clientDataJSON,
                authenticatorData: publicKey.response.authenticatorData,
                transports: credential.response.getTransports(),
                publicKey: responsePublicKey ? winupArrayBufferToBase64(responsePublicKey) : null,
                publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm(),
                attestationObject: publicKey.response.attestationObject,
            };
        }

        if (credential.response instanceof AuthenticatorAssertionResponse) {
            response = {
                clientDataJSON: publicKey.response.clientDataJSON,
                authenticatorData: publicKey.response.authenticatorData,
                signature: publicKey.response.signature,
                userHandle: publicKey.response?.userHandle || undefined,
            };
        }

        return {
            id: publicKey.id,
            rawId: publicKey.id,
            response,
            authenticatorAttachment,
            clientExtensionResults,
            type,
        };
    };

    // Wraps response to AuthenticatorAttestationResponse object
    const createAttestationResponse = function(publicKey) {
        const response = {
            attestationObject: winupBase64ToArrayBuffer(publicKey.response.attestationObject),
            clientDataJSON: winupBase64ToArrayBuffer(publicKey.response.clientDataJSON),
            getAuthenticatorData: () => winupBase64ToArrayBuffer(publicKey.response?.authenticatorData),
            getPublicKey: () =>
                publicKey.response?.publicKey ? winupBase64ToArrayBuffer(publicKey.response?.publicKey) : null,
            getPublicKeyAlgorithm: () => publicKey.response?.publicKeyAlgorithm,
            getTransports: () => [ 'internal' ]
        };

        const prfResponse = publicKey.response?.clientExtensionResults?.prf;
        if (prfResponse) {
            if (prfResponse?.results?.first) {
                response['clientExtensionResults'] =
                { prf: { results: { first: winupBase64ToArrayBuffer(prfResponse?.results?.first) } } };
            } else if (prfResponse?.enabled) {
                response['clientExtensionResults'] = { prf: prfResponse };
            }
        }

        return Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
    };

    // Wraps response to AuthenticatorAssertionResponse object
    const createAssertionResponse = function(publicKey) {
        const response = {
            authenticatorData: winupBase64ToArrayBuffer(publicKey.response?.authenticatorData),
            clientDataJSON: winupBase64ToArrayBuffer(publicKey.response?.clientDataJSON),
            signature: winupBase64ToArrayBuffer(publicKey.response?.signature),
            userHandle: publicKey.response?.userHandle ? winupBase64ToArrayBuffer(publicKey.response?.userHandle) : null
        };

        const prfResponse = publicKey.response?.clientExtensionResults?.prf?.results?.first;
        if (prfResponse) {
            response['clientExtensionResults'] = { prf: { results: { first: winupBase64ToArrayBuffer(prfResponse) } } };
        }

        return Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
    };

    // Wraps public key to PublicKeyCredential object
    const createPublicKeyCredential = function(publicKey) {
        const authenticatorResponse = publicKey?.response?.attestationObject
            ? createAttestationResponse(publicKey)
            : createAssertionResponse(publicKey);
        const clientExtensionResults =
            authenticatorResponse?.clientExtensionResults || publicKey?.response?.clientExtensionResults || {};
        const publicKeyCredential = {
            authenticatorAttachment: publicKey.authenticatorAttachment,
            id: publicKey.id,
            rawId: winupBase64ToArrayBuffer(publicKey.id),
            response: authenticatorResponse,
            type: publicKey.type,
            clientExtensionResults: () => clientExtensionResults,
            getClientExtensionResults: () => clientExtensionResults,
            toJSON: () => winupPublicKeyCredentialJson(publicKeyCredential, publicKey)
        };

        return Object.setPrototypeOf(publicKeyCredential, PublicKeyCredential.prototype);
    };

    /**
     * Posts a message to extension's content script and waits for response
     * @async
     * @param {object} request
     * @param {AbortSignal=} signal
     * @returns {Promise<object>}
     * @throws {unknown} if `AbortSignal`
     */
    function serialize(value) {
        if (value instanceof ArrayBuffer) return winupArrayBufferToBase64(value);
        if (ArrayBuffer.isView(value)) return winupArrayBufferToBase64(value.buffer.slice(value.byteOffset,value.byteOffset+value.byteLength));
        if (Array.isArray(value)) return value.map(serialize);
        if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,serialize(v)]));
        return value;
    }
    const postMessageToExtension = function(request, signal) {
        return new Promise((resolve,reject)=> {
            const id=crypto.randomUUID().replaceAll('-','');
            let timeout;
            function cleanup() { clearTimeout(timeout); document.removeEventListener('winup-passkeys-response',listener); signal?.removeEventListener('abort',abort); }
            function abort() {
                cleanup(); document.dispatchEvent(new CustomEvent('winup-passkeys-request',{detail:JSON.stringify({action:'abort',requestId:id})}));
                reject(new DOMException('Операция отменена','AbortError'));
            }
            function listener(event) {
                if(typeof event.detail!=='string') return;
                let response; try { response=JSON.parse(event.detail); } catch { return; }
                if(response.requestId!==id) return;
                cleanup();
                if(response.error) {
                    if(response.error==='not_found' && request.action==='passkeys_get') resolve({fallback:true});
                    else if(response.error==='TypeError') reject(new TypeError('Некорректные параметры ключа доступа'));
                    else {
                        const hints={not_running:'Запустите WinUp и повторите создание ключа доступа.',not_installed:'Подключите расширение в меню WinUp.',not_paired:'Свяжите расширение с WinUp через его значок в браузере.',locked:'Откройте базу WinUp и повторите запрос.'};
                        reject(new DOMException(hints[response.error] || response.error,['SecurityError','InvalidStateError','NotSupportedError','AbortError'].includes(response.error) ? response.error : 'NotAllowedError'));
                    }
                } else resolve(response);
            }
            if(signal?.aborted) return abort();
            // Serialize before registering listeners/timers: cyclic or oversized
            // page-supplied options must not leave an unreachable pending request.
            let payload;
            try {
                payload=JSON.stringify({...serialize(request),requestId:id});
                if(payload.length>60000) throw new TypeError('Слишком большой запрос ключа доступа');
            } catch {
                reject(new TypeError('Некорректные параметры ключа доступа')); return;
            }
            document.addEventListener('winup-passkeys-response',listener);
            signal?.addEventListener('abort',abort,{once:true});
            const lifetime=Math.max(5000,Math.min(Number(request.publicKey?.timeout)||120000,120000));
            timeout=setTimeout(abort,lifetime);
            document.dispatchEvent(new CustomEvent('winup-passkeys-request',{detail:payload}));
        });
    };
    const waitForFocus = function (signal) {
        /*
        Some browsers (Firefox, Safari) reject requests to original `navigator.credentials.create/get` if the page
        is out of focus (when the user selects a passkey in KeePassXC-desktop).

        See <https://www.w3.org/TR/webauthn-2/#sctn-abortoperation:~:text=The%20visibility,aborted>

        `document.visibilityState` is not suitable: if the page is visible, but the focus is on another application
        (or DevTools), the request will be rejected.
        */
        return new Promise((resolve,reject) => {
            if(signal?.aborted) return reject(new DOMException('Операция отменена','AbortError'));
            if (document.hasFocus()) {
                return resolve();
            }
            const cleanup=()=> { document.removeEventListener('focus',focused,true); window.removeEventListener('focus',focused,true); document.removeEventListener('visibilitychange',focused); signal?.removeEventListener('abort',aborted); };
            const focused=()=> { if(document.hasFocus()) { cleanup(); resolve(); } };
            const aborted=()=> { cleanup(); reject(new DOMException('Операция отменена','AbortError')); };
            document.addEventListener('focus',focused,{capture:true,passive:true});
            window.addEventListener('focus',focused,{capture:true,passive:true});
            document.addEventListener('visibilitychange',focused,{passive:true});
            signal?.addEventListener('abort',aborted,{once:true});
        });
    };

    /**
     * Throws errors to a correct exceptions
     * @param {number} errorCode
     * @param {string} errorMessage
     * @returns {never}
     */
    const throwError = function(errorCode, errorMessage) {
        if ([ PASSKEYS_DOMAIN_RPID_MISMATCH, PASSKEYS_DOMAIN_IS_NOT_VALID ].includes(errorCode)) {
            throw new DOMException(errorMessage, DOMException.SECURITY_ERR);
        }

        if (
            [
                PASSKEYS_NO_SUPPORTED_ALGORITHMS,
                PASSKEYS_EVAL_BY_CREDENTIAL_NOT_SUPPORTED,
                PASSKEYS_EVAL_BY_CREDENTIAL_NOT_EMPTY
            ].includes(errorCode)
        ) {
            throw new DOMException(errorMessage, DOMException.NOT_SUPPORTED_ERR);
        }

        if (errorCode === PASSKEYS_EVAL_BY_CREDENTIAL_NOT_FOUND) {
            throw new DOMException(errorMessage, DOMException.SYNTAX_ERR);
        }

        if ([ PASSKEYS_INVALID_CHALLENGE, PASSKEYS_INVALID_USER_ID ].includes(errorCode)) {
            throw new TypeError(errorMessage);
        }

        if (
            [
                PASSKEYS_NO_LOGINS_FOUND,
                PASSKEYS_CREDENTIAL_IS_EXCLUDED,
                PASSKEYS_REQUEST_CANCELED,
                PASSKEYS_WAIT_FOR_LIFETIMER,
                PASSKEYS_ATTESTATION_NOT_SUPPORTED,
                PASSKEYS_INVALID_URL_PROVIDED,
                PASSKEYS_INVALID_USER_VERIFICATION,
                PASSKEYS_EMPTY_PUBLIC_KEY,
                PASSKEYS_UNKNOWN_ERROR,
                PASSKEYS_ORIGIN_NOT_ALLOWED,
            ].includes(errorCode)
        ) {
            throw new DOMException(errorMessage, 'NotAllowedError');
        }

        throw new DOMException(errorMessage, 'UnknownError');
    };

    const originalCredentials = navigator.credentials;

    const passkeysCredentials = Object.assign(Object.create(originalCredentials), {
        async create(options) {
            if (!options?.publicKey) {
                return originalCredentials.create.call(originalCredentials,options);
            }

            const response = await postMessageToExtension({
                action: 'passkeys_create',
                publicKey: options.publicKey
            }, options?.signal);

            if (!response.publicKey) {
                if (!response.fallback) {
                    throwError(response?.errorCode, response?.errorMessage);
                }
                await waitForFocus(options?.signal);
                return originalCredentials.create.call(originalCredentials,options);
            }

            return createPublicKeyCredential(response.publicKey);
        },
        async get(options) {
            if (!options?.publicKey || options?.mediation === 'silent') {
                return originalCredentials.get.call(originalCredentials,options);
            }

            if (options?.mediation === 'conditional') {
                return originalCredentials.get.call(originalCredentials,options);
            }

            const response = await postMessageToExtension({
                action: 'passkeys_get',
                publicKey: options.publicKey
            }, options?.signal);

            if (!response.publicKey) {
                if (!response.fallback) {
                    throwError(response?.errorCode, response?.errorMessage);
                }
                await waitForFocus(options?.signal);
                return originalCredentials.get.call(originalCredentials,options);
            }

            return createPublicKeyCredential(response.publicKey);
        },
        async store(credential) {
            return originalCredentials.store.call(originalCredentials,credential);
        },
        async preventSilentAccess() {
            return originalCredentials.preventSilentAccess.call(originalCredentials);
        }
    });

    // MAIN and isolated document_start scripts can run in different orders.
    // Let both install their event listeners before the first request.
    await new Promise(resolve => setTimeout(resolve, 0));
    const available=await postMessageToExtension({action:'available'});
    if(!available.enabled) return;
    try {
        Object.defineProperty(navigator,'credentials',{value:passkeysCredentials});
        // Google and other sites probe platform UV before offering registration.
        // WinUp provides UV with its own verified master password / Windows Hello.
        const originalAvailable=PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.bind(PublicKeyCredential);
        Object.defineProperty(PublicKeyCredential,'isUserVerifyingPlatformAuthenticatorAvailable',{configurable:true,value:async()=>{
            const setting=await postMessageToExtension({action:'available'});
            return setting.enabled ? true : originalAvailable ? originalAvailable() : false;
        }});
    }
    catch { /* A browser that disallows interception keeps its native provider. */ }
})();
