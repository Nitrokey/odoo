# Part of Odoo. See LICENSE file for full copyright and licensing details.
from collections import defaultdict

from werkzeug.exceptions import NotFound

from odoo import http
from odoo.http import request
from odoo.addons.mail.models.discuss.mail_guest import add_guest_to_context
from odoo.addons.mail.tools.discuss import Store
from odoo.addons.mail.tools.jwt import InvalidVapidError
from odoo.osv import expression

# HttpOnly cookie used to store the push refresh token (30-day sliding credential).
_PUSH_REFRESH_COOKIE = 'push_refresh_token'
_PUSH_REFRESH_COOKIE_MAX_AGE = 30 * 24 * 60 * 60  # seconds


class WebclientController(http.Controller):
    """Routes for the web client."""

    @http.route("/mail/action", methods=["POST"], type="json", auth="public")
    @add_guest_to_context
    def mail_action(self, **kwargs):
        """Execute actions and returns data depending on request parameters.
        This is similar to /mail/data except this method can have side effects.
        """
        return self._process_request(**kwargs)

    @http.route("/mail/data", methods=["POST"], type="json", auth="public", readonly=True)
    @add_guest_to_context
    def mail_data(self, **kwargs):
        """Returns data depending on request parameters.
        This is similar to /mail/action except this method should be read-only.
        """
        return self._process_request(**kwargs)

    @http.route("/web/push/device/register", methods=["POST"], type="json", auth="user")
    def push_device_register(self, **kwargs):
        """Register (or update) a push subscription for the logged-in user.

        Uses a JSON-RPC route (instead of a plain ORM call) so that the server can
        set the refresh token as an HttpOnly cookie, via ``request.future_response``,
        in the same response that returns the short-lived access token.

        Expects the fields from PushSubscription.toJSON() plus ``vapid_public_key``
        and optionally ``previous_endpoint``.
        """
        try:
            result = request.env["mail.push.device"].register_devices(**kwargs)
        except InvalidVapidError:
            return {'error': 'odoo.addons.mail.tools.jwt.InvalidVapidError'}
        if not result:
            return {'error': 'registration_failed'}
        request.future_response.set_cookie(
            _PUSH_REFRESH_COOKIE,
            result['refresh_token'],
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=_PUSH_REFRESH_COOKIE_MAX_AGE,
            path='/web/push/device/',
        )
        return {'token': result['token']}

    @http.route("/web/push/device/token/rotate", methods=["POST"], type="json", auth="public")
    def push_device_token_rotate(self, previousEndpoint=None, **kwargs):
        """Exchange a valid refresh token for a new access + refresh token pair.

        The service worker calls this route (with ``credentials: "include"``) when
        POST /web/push/device/refresh returns ``{'reason': 'expired'}``. The browser
        attaches the HttpOnly refresh token cookie automatically; JavaScript cannot
        read it.

        On success a new refresh token is set as a replacement HttpOnly cookie (via
        ``request.future_response``) and the new access token is returned in the JSON
        body for storage in IndexedDB.
        """
        refresh_token = request.httprequest.cookies.get(_PUSH_REFRESH_COOKIE)
        if not refresh_token:
            return {'error': 'no_refresh_token'}
        result = request.env["mail.push.device"].sudo()._rotate_tokens(
            refresh_token=refresh_token,
            previous_endpoint=previousEndpoint,
        )
        if not result:
            return {'error': 'invalid_token'}
        request.future_response.set_cookie(
            _PUSH_REFRESH_COOKIE,
            result['refresh_token'],
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=_PUSH_REFRESH_COOKIE_MAX_AGE,
            path='/web/push/device/',
        )
        return {'token': result['access_token']}

    @http.route("/web/push/device/refresh", methods=["POST"], type="json", auth="public")
    def push_device_refresh(self, token, endpoint, keys, vapid_public_key,
                            previousEndpoint=None, expirationTime=None, **kwargs):
        """Refresh a push subscription endpoint without requiring an active session.

        The service worker calls this route from its pushsubscriptionchange handler when
        the browser renews a push subscription and the user's Odoo session may have
        expired. Authentication is based on the short-lived access token (1 hour)
        issued by /web/push/device/register and stored by the service worker in IndexedDB.

        Returns {'success': True, 'token': new_token} on success so the service worker
        can update its stored access token. Returns {'success': False, 'reason': 'expired'}
        when the access token has expired, signalling the service worker to call
        /web/push/device/token/rotate to obtain a new pair via the HttpOnly refresh cookie.

        :param str token: access token from the service worker's IndexedDB
        :param str endpoint: new push subscription endpoint URL
        :param dict keys: new push subscription keys (p256dh, auth)
        :param str vapid_public_key: server VAPID public key (for cross-check)
        :param str previousEndpoint: old endpoint used to locate the device record
        :param expirationTime: optional new expiration timestamp (camelCase from subscription.toJSON())
        """
        return request.env["mail.push.device"].sudo().refresh_subscription_by_token(
            token=token,
            endpoint=endpoint,
            keys=keys,
            vapid_public_key=vapid_public_key,
            previous_endpoint=previousEndpoint,
            expiration_time=expirationTime,
        )

    def _process_request(self, **kwargs):
        store = Store()
        request.update_context(**kwargs.get("context", {}))
        self._process_request_for_all(store, **kwargs)
        if not request.env.user._is_public():
            self._process_request_for_logged_in_user(store, **kwargs)
        if request.env.user._is_internal():
            self._process_request_for_internal_user(store, **kwargs)
        return store.get_result()

    def _process_request_for_all(self, store, **kwargs):
        if "init_messaging" in kwargs:
            if not request.env.user._is_public():
                user = request.env.user.sudo(False)
                user._init_messaging(store)
            else:
                guest = request.env["mail.guest"]._get_guest_from_context()
                if not guest:
                    raise NotFound()
            member_domain = [
                ("is_self", "=", True),
                "|",
                ("fold_state", "in", ("open", "folded")),
                ("rtc_inviting_session_id", "!=", False),
            ]
            channels_domain = [("channel_member_ids", "any", member_domain)]
            channel_types = kwargs["init_messaging"].get("channel_types")
            if channel_types:
                channels_domain = expression.AND(
                    [channels_domain, [("channel_type", "in", channel_types)]]
                )
            store.add(request.env["discuss.channel"].search(channels_domain))

    def _process_request_for_logged_in_user(self, store, **kwargs):
        if kwargs.get("failures"):
            domain = [
                ("author_id", "=", request.env.user.partner_id.id),
                ("notification_status", "in", ("bounce", "exception")),
                ("mail_message_id.message_type", "!=", "user_notification"),
                ("mail_message_id.model", "!=", False),
                ("mail_message_id.res_id", "!=", 0),
            ]
            # sudo as to not check ACL, which is far too costly
            # sudo: mail.notification - return only failures of current user as author
            notifications = request.env["mail.notification"].sudo().search(domain, limit=100)
            found = defaultdict(list)
            for message in notifications.mail_message_id:
                found[message.model].append(message.res_id)
            existing = {
                model: set(request.env[model].browse(ids).exists().ids)
                for model, ids in found.items()
            }
            valid = notifications.filtered(
                lambda n: n.mail_message_id.res_id in existing[n.mail_message_id.model]
            )
            lost = notifications - valid
            # might break readonly status of mail/data, but in really rare cases
            # and solves it by removing useless notifications
            if lost:
                lost.sudo().unlink()  # no unlink right except admin, ok to remove as lost anyway
            valid.mail_message_id._message_notifications_to_store(store)

    def _process_request_for_internal_user(self, store, **kwargs):
        if kwargs.get("systray_get_activities"):
            # sudo: bus.bus: reading non-sensitive last id
            bus_last_id = request.env["bus.bus"].sudo()._bus_last_id()
            groups = request.env["res.users"]._get_activity_groups()
            store.add(
                {
                    "activityCounter": sum(group.get("total_count", 0) for group in groups),
                    "activity_counter_bus_id": bus_last_id,
                    "activityGroups": groups,
                }
            )
        if kwargs.get("canned_responses"):
            domain = [
                "|",
                ("create_uid", "=", request.env.user.id),
                ("group_ids", "in", request.env.user.groups_id.ids),
            ]
            store.add(request.env["mail.canned.response"].search(domain))
