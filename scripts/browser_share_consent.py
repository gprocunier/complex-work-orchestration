"""Private final-disclosure bindings and a registered offline DOM boundary.

The DOM contract is for complete, controlled offline fixtures. It makes no
claim about coverage of a live conversation UI and never discovers live routes.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from cwo_core.outbound_screen import OutboundRefused, require_clean
from cwo_core.prepared_outbound import PreparedSource


class BrowserActionRefused(ValueError):
    """Static diagnostic; packet, conversation and result remain private."""


def require(condition, message):
    if not condition:
        raise BrowserActionRefused(message)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise BrowserActionRefused("Share disclosure is not finite UTF-8 JSON.") from None


def _keys(value, names):
    return type(value) is dict and set(value) == set(names.split())


def _text(value):
    return type(value) is str and bool(value.strip())


@dataclass(frozen=True, slots=True, eq=False)
class ShareConsent:
    """Exact-object, expiring consent; only the issuing parent holds its binding."""


def valid_result_url(url, origin):
    if type(url) is not str:
        return False
    try:
        parsed = urlsplit(url)
        return (parsed.scheme + "://" + parsed.netloc == origin
                and parsed.geturl() == url
                and re.fullmatch(r"/(?:s|share)/[a-zA-Z0-9_-]+", parsed.path) is not None
                and not parsed.query and not parsed.fragment)
    except ValueError:
        return False


def require_existing_share(observation, action_sha256):
    existing = observation["existing_share"]
    if existing is None:
        return
    require(_keys(existing, "url document_id conversation_url action_sha256"),
            "Share result lacks an observed conversation and action binding.")
    require(existing["document_id"] == observation["document_id"]
            and existing["conversation_url"] == observation["conversation_url"]
            and existing["action_sha256"] == action_sha256,
            "Observed share result belongs to another document, conversation or action.")
    require(valid_result_url(existing["url"], observation["selection"]["origin"]),
            "Observed share result URL is unsupported.")


def _require_request_turn(selection, payload):
    messages = selection["messages"]
    users = [message for message in messages if message["role"] == "user"]
    require(messages[-1]["role"] == "assistant" and _text(messages[-1]["content"]) and bool(users),
            "Complete share disclosure requires the generated assistant response.")
    require(users[-1]["content"] == payload,
            "Observed conversation does not contain the original prepared request turn.")


def require_observation(observation, context, action_sha256):
    selection = context["share"]
    require(_keys(observation, "document_id conversation_url selection coverage representation existing_share"),
            "Share disclosure observation is incomplete.")
    require(observation["coverage"] == "complete" and _text(observation["document_id"]),
            "Complete share disclosure coverage and document identity are required.")
    require(canonical(observation["selection"]) == canonical(selection),
            "Observed whole conversation differs from the original share selection.")
    _require_request_turn(selection, context["payload"])
    require(observation["conversation_url"] == selection["origin"] + "/c/" + selection["conversation_id"],
            "Observed share conversation URL differs from the original selection.")
    require(type(observation["representation"]) is str
            and observation["representation"] == canonical(selection).decode("utf-8"),
            "Observed final share representation differs from the complete conversation.")
    require_existing_share(observation, action_sha256)


def disclosure_source(context, metadata, observation):
    return {"context": context, "original_prepared": metadata,
            "disclosure": {key: value for key, value in observation.items() if key != "existing_share"}}


def prepare_disclosure(context, metadata, observation, files):
    """Screen decoded messages and the exact final representation, then freeze both."""
    source = disclosure_source(context, metadata, observation)
    try:
        decoded = "\n".join(message["content"] for message in observation["selection"]["messages"])
        require_clean(decoded, surface="ChatGPT sharing decoded conversation")
        screened = require_clean(observation["representation"], surface="ChatGPT sharing final disclosure",
                                 content_type="application/json")
        return PreparedSource.capture(source, files).bind(source, screened)
    except (OutboundRefused, ValueError, UnicodeError):
        raise BrowserActionRefused("Final conversation disclosure screening refused sharing.") from None


def require_disclosure(prepared, context, metadata, observation):
    try:
        prepared.require_unchanged(disclosure_source(context, metadata, observation), observation["representation"])
    except (OutboundRefused, ValueError, UnicodeError):
        raise BrowserActionRefused("Share disclosure or original preparation changed after consent.") from None


def require_result(raw, observation, action_sha256):
    require(type(raw) is bytes, "Share creation returned an unsupported result representation.")
    try:
        url = raw.decode("utf-8")
    except UnicodeError:
        raise BrowserActionRefused("Share creation returned an unreadable result URL.") from None
    require_existing_share(observation, action_sha256)
    require(observation["existing_share"] is not None
            and observation["existing_share"]["url"] == url,
            "Returned share URL lacks a matching observed action and conversation.")


# A JSHandle pins the actual Document object, including across document.open().
# All reads and the guarded click run synchronously in its execution context.
# Fixture markup explicitly declares coverage; this is not a live UI reader.
_SHARE_SNAPSHOT_JS = r"""
  const fail = () => { throw new Error('Offline share document contract refused.'); };
  const original = pin.document;
  if (original !== document || pin.root !== document.documentElement || !pin.root?.isConnected) fail();
  const roots = document.querySelectorAll('[data-cwo-offline-share-fixture]');
  if (roots.length !== 1) fail();
  const root = roots[0];
  // Only a controlled plaintext fixture can assert complete coverage here.
  // textContent alone would silently omit an image, upload, embedded document,
  // link destination or other rich surface from the disclosed representation.
  if (root.querySelector('img,video,audio,iframe,object,embed,svg,canvas,picture,source,track,input,textarea,select,' +
                         '[src],[srcset],[data-attachment],[data-upload]')) fail();
  if ([root, ...root.querySelectorAll('*')].some(node => !!node.shadowRoot)) fail();
  if (!original.__cwoOfflineShareDocumentId) {
    const words = crypto.getRandomValues(new Uint32Array(4));
    Object.defineProperty(original, '__cwoOfflineShareDocumentId', {value: [...words].join('-')});
  }
  const messages = [...document.querySelectorAll('[data-message-author-role]')].map(el => {
    if (!root.contains(el) || el.querySelector('[data-message-author-role]')) fail();
    const plainTags = new Set(['DIV', 'SPAN', 'P', 'PRE', 'CODE']);
    for (const part of [el, ...el.querySelectorAll('*')]) {
      if (!plainTags.has(part.tagName)) fail();
      for (const attribute of part.attributes) {
        if (['data-message-author-role', 'data-message-id'].includes(attribute.name)) continue;
        if (attribute.name === 'style' && part.style.whiteSpace === 'pre-wrap') {
          // CSSOM can expand this shorthand into its two equivalent longhands.
          const properties = [...part.style].sort().join(',');
          if (properties === 'white-space' || properties === 'text-wrap-mode,white-space-collapse') continue;
        }
        fail();
      }
    }
    return {message_id: el.getAttribute('data-message-id'),
            role: el.getAttribute('data-message-author-role'), content: el.textContent};
  });
  const representations = document.querySelectorAll('[data-cwo-share-representation]');
  const results = document.querySelectorAll('[data-cwo-share-result]');
  if (representations.length !== 1 || results.length > 1) fail();
  if (representations[0].children.length) fail();
  const result = results[0];
  const observation = {
    document_id: original.__cwoOfflineShareDocumentId,
    conversation_url: location.href,
    selection: {origin: location.origin, conversation_id: root.getAttribute('data-conversation-id'),
                purpose: root.getAttribute('data-share-purpose'), messages},
    coverage: root.getAttribute('data-cwo-offline-share-fixture'),
    representation: representations[0].textContent,
    existing_share: result ? {url: result.textContent,
      document_id: result.getAttribute('data-document-id'),
      conversation_url: result.getAttribute('data-conversation-url'),
      action_sha256: result.getAttribute('data-action-sha256')} : null
  };
"""
_SHARE_OBSERVE_SCRIPT = "(pin) => {" + _SHARE_SNAPSHOT_JS + "return observation; }"
_SHARE_CREATE_SCRIPT = "(pin, expectation) => {" + _SHARE_SNAPSHOT_JS + r"""
  const canonical = value => {
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(
      key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
    return JSON.stringify(value);
  };
  if (canonical(observation) !== canonical(expectation.observation) || observation.coverage !== 'complete') fail();
  if (observation.existing_share && (
      observation.existing_share.document_id !== observation.document_id ||
      observation.existing_share.conversation_url !== observation.conversation_url ||
      observation.existing_share.action_sha256 !== expectation.action_sha256)) fail();
  const buttons = document.querySelectorAll('button[data-cwo-create-share]');
  if (buttons.length !== 1 || buttons[0].disabled || !buttons[0].isConnected) fail();
  const button = buttons[0];
  button.setAttribute('data-document-id', observation.document_id);
  button.setAttribute('data-conversation-url', observation.conversation_url);
  button.setAttribute('data-action-sha256', expectation.action_sha256);
  button.setAttribute('data-admission-sha256', expectation.admission_sha256);
  pin.click.call(button);
  const returned = document.querySelectorAll('[data-cwo-share-result]');
  if (returned.length !== 1) fail();
  return returned[0].textContent;
}"""


class OfflineDOMShareBoundary:
    """Explicit registration for controlled offline fixtures with complete coverage.

    An original Document handle and one synchronous browser operation bind the
    observed URL, complete content and representation to the single create click.
    There is no legacy/social/clipboard fallback or live coverage inference.
    """

    def __init__(self, page):
        self._document = self._registered_document = page.evaluate_handle(
            "() => ({document, root: document.documentElement, click: HTMLElement.prototype.click})")

    def _evaluate(self, script, argument=None):
        require(self._document is self._registered_document, "Registered offline document handle changed.")
        return self._document.evaluate(script, argument)

    def observe(self):
        return self._evaluate(_SHARE_OBSERVE_SCRIPT)

    def create(self, expectation, *, timeout_seconds, max_output_bytes):
        return self._evaluate(_SHARE_CREATE_SCRIPT, expectation).encode("utf-8")

    def result(self):
        return self.observe()
