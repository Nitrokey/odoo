/* eslint-env serviceworker */
/* eslint-disable no-restricted-globals */

/**
 * Encode an ArrayBuffer as a base64url string without padding.
 * Mirrors _arrayBufferToBase64() in webclient.js, but uses the global btoa()
 * instead of window.btoa() since window is not available in service workers.
 *
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function arrayBufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// --- IndexedDB helpers: persist device token across service worker restarts ---
const _PUSH_DB_NAME = "odoo_push";
const _PUSH_DB_VERSION = 1;
const _PUSH_STORE_NAME = "device";
const _PUSH_TOKEN_KEY = "token";

function _openPushDb() {
    return new Promise((resolve, reject) => {
        const req = indexedDB.open(_PUSH_DB_NAME, _PUSH_DB_VERSION);
        req.onupgradeneeded = (event) => {
            event.target.result.createObjectStore(_PUSH_STORE_NAME);
        };
        req.onsuccess = (event) => resolve(event.target.result);
        req.onerror = (event) => reject(event.target.error);
    });
}

async function _storePushDeviceToken(token) {
    const db = await _openPushDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(_PUSH_STORE_NAME, "readwrite");
        tx.objectStore(_PUSH_STORE_NAME).put(token, _PUSH_TOKEN_KEY);
        tx.oncomplete = () => resolve();
        tx.onerror = (event) => reject(event.target.error);
    });
}

async function _loadPushDeviceToken() {
    const db = await _openPushDb();
    return new Promise((resolve, reject) => {
        const tx = db.transaction(_PUSH_STORE_NAME, "readonly");
        const req = tx.objectStore(_PUSH_STORE_NAME).get(_PUSH_TOKEN_KEY);
        req.onsuccess = (event) => resolve(event.target.result ?? null);
        req.onerror = (event) => reject(event.target.error);
    });
}

async function openDiscussChannel(channelId, action) {
    const discussURLRegexes = [
        new RegExp("/odoo/discuss"),
        new RegExp(`/odoo/\\d+/action-${action}`),
        new RegExp(`/odoo/action-${action}`),
    ];
    let targetClient;
    for (const client of await self.clients.matchAll({
        type: "window",
        includeUncontrolled: true,
    })) {
        if (!targetClient || discussURLRegexes.some((r) => r.test(new URL(client.url).pathname))) {
            targetClient = client;
        }
    }
    if (!targetClient) {
        targetClient = await self.clients.openWindow(
            `/odoo/action-${action}?active_id=discuss.channel_${channelId}`
        );
    }
    await targetClient.focus();
    targetClient.postMessage({ action: "OPEN_CHANNEL", data: { id: channelId } });
}

self.addEventListener("notificationclick", (event) => {
    event.notification.close();
    if (event.notification.data) {
        const { action, model, res_id } = event.notification.data;
        if (model === "discuss.channel") {
            event.waitUntil(openDiscussChannel(res_id, action));
        } else {
            const modelPath = model.includes(".") ? model : `m-${model}`;
            clients.openWindow(`/odoo/${modelPath}/${res_id}`);
        }
    }
});
self.addEventListener("push", (event) => {
    const notification = event.data.json();
    event.waitUntil(handlePushEvent(notification));
});

/** @type {Map<string, Function>} string is correlationId and Function is handler */
self.handlePushEventMessageFns = new Map();

self.addEventListener("message", (event) => {
    const { type, payload } = event.data;
    if (type === "notification-display-response") {
        const fn = self.handlePushEventMessageFns.get(payload.correlationId);
        if (fn) {
            self.handlePushEventMessageFns.delete(payload.correlationId);
            fn({ data: event.data });
        }
    }
    if (type === "STORE_PUSH_TOKEN" && payload?.token) {
        event.waitUntil(_storePushDeviceToken(payload.token));
    }
});

async function handlePushEvent(notification) {
    const { model, res_id } = notification.options?.data || {};
    const correlationId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    let timeoutId;
    let promResolve;
    const onHandlePushEventMessage = ({ data = {} }) => {
        const { type, payload } = data;
        if (type === "notification-display-response" && payload.correlationId === correlationId) {
            clearTimeout(timeoutId);
            promResolve?.();
        }
    };
    return new Promise((resolve) => {
        promResolve = resolve;
        self.handlePushEventMessageFns.set(correlationId, onHandlePushEventMessage);
        self.clients.matchAll({ includeUncontrolled: true, type: "window" }).then((clients) => {
            clients.forEach((client) =>
                client.postMessage({
                    type: "notification-display-request",
                    payload: { correlationId, model, res_id },
                })
            );
        });
        timeoutId = setTimeout(() => {
            resolve(self.registration.showNotification(notification.title, notification.options));
        }, 500);
    });
}
self.addEventListener("pushsubscriptionchange", (event) => {
    event.waitUntil(
        (async () => {
            if (!event.oldSubscription) {
                return;
            }
            const newSubscription = await self.registration.pushManager.subscribe(
                event.oldSubscription.options
            );
            const subscriptionData = newSubscription.toJSON();
            const oldEndpoint = event.oldSubscription.endpoint;

            // Encode the VAPID public key as base64url to pass to the server for validation.
            const vapid_public_key = arrayBufferToBase64Url(
                newSubscription.options.applicationServerKey
            );

            /**
             * Attempt to refresh the subscription using the given access token.
             * On success the server rotates the access token and returns the new value.
             * @param {string} accessToken
             * @returns {Object|null} server result or null on network error
             */
            async function tryRefresh(accessToken) {
                try {
                    const resp = await fetch("/web/push/device/refresh", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                            jsonrpc: "2.0",
                            method: "call",
                            id: 1,
                            params: {
                                token: accessToken,
                                ...subscriptionData,
                                vapid_public_key,
                                previousEndpoint: oldEndpoint,
                            },
                        }),
                    });
                    const json = await resp.json();
                    return json.result ?? null;
                } catch {
                    return null;
                }
            }

            // 1. Prefer access-token-based refresh: works even when the Odoo session
            //    has expired (access token is stored in IndexedDB, not a session cookie).
            const token = await _loadPushDeviceToken().catch(() => null);
            if (token) {
                const result = await tryRefresh(token);
                if (result?.success) {
                    // Server rotated the access token; persist the new one.
                    if (result.token) {
                        await _storePushDeviceToken(result.token);
                    }
                    return;
                }

                // 2. Access token is valid but expired: use the HttpOnly refresh token
                //    cookie (attached automatically by the browser) to rotate both tokens.
                if (result?.reason === "expired") {
                    try {
                        const rotateResp = await fetch("/web/push/device/token/rotate", {
                            method: "POST",
                            credentials: "include", // browser attaches the HttpOnly cookie
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ previousEndpoint: oldEndpoint }),
                        });
                        const rotateJson = await rotateResp.json();
                        if (rotateJson.token) {
                            await _storePushDeviceToken(rotateJson.token);
                            const retryResult = await tryRefresh(rotateJson.token);
                            if (retryResult?.success) {
                                if (retryResult.token) {
                                    await _storePushDeviceToken(retryResult.token);
                                }
                                return;
                            }
                        }
                    } catch {
                        // fall through to session-based fallback below
                    }
                }
            }

            // 3. Fallback: session-based registration. Requires an active session cookie
            //    but also sets a fresh refresh token cookie for future renewals.
            try {
                const resp = await fetch("/web/push/device/register", {
                    method: "POST",
                    credentials: "include",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        ...subscriptionData,
                        vapid_public_key,
                        previousEndpoint: oldEndpoint,
                    }),
                });
                const json = await resp.json();
                if (json.token) {
                    await _storePushDeviceToken(json.token);
                }
            } catch {
                // Nothing more we can do; the subscription will be renewed on next login.
            }
        })()
    );
});
