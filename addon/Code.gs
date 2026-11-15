/**
 * MailGuard Gmail add-on.
 *
 * Thin client: when the user opens an email, it reads that one message, sends it to the
 * MailGuard backend over HTTPS with an HMAC signature, and renders the returned verdict.
 * All detection logic lives in the backend.
 *
 * Required Script Properties (Project Settings -> Script Properties):
 *   BACKEND_URL  - e.g. https://mailguard-backend-<number>.<region>.run.app (no trailing slash)
 *   HMAC_SECRET  - the shared secret stored in Google Secret Manager
 */

/** Must match the backend setting MAILGUARD_MAX_MESSAGE_BYTES. */
var MAX_MESSAGE_BYTES = 2 * 1024 * 1024;

// "safe" is shown as "Low risk": a scanner can find evidence of danger, not prove safety.
var VERDICT_STYLES = {
  safe: { label: 'Low risk', color: '#188038' },
  suspicious: { label: 'Suspicious', color: '#E37400' },
  malicious: { label: 'Malicious', color: '#D93025' },
  inconclusive: { label: 'Inconclusive', color: '#5F6368' },
};

/** An error whose message is safe to show to the user. */
class MailGuardError extends Error {
  constructor(message) {
    super(message);
    this.name = 'MailGuardError';
  }
}

// ---------------------------------------------------------------------------
// Triggers (entry points declared in appsscript.json)
// ---------------------------------------------------------------------------

/** Shown when the add-on is opened without an email selected. */
function onHomepage() {
  return buildMessageCard_('Open an email to see its MailGuard risk analysis.');
}

/** Runs every time the user opens an email. */
function onGmailMessageOpen(e) {
  try {
    var rawMessage = getCurrentMessageRaw_(e);
    var result = analyzeMessage_(rawMessage);
    return buildResultCard_(result);
  } catch (err) {
    if (err instanceof MailGuardError) {
      return buildMessageCard_(err.message);
    }
    // Log only the error type: never email content or secrets.
    console.error('MailGuard: unexpected error (' + err.name + ')');
    return buildMessageCard_('Something went wrong while analyzing this email. Please try again.');
  }
}

// ---------------------------------------------------------------------------
// Reading the email
// ---------------------------------------------------------------------------

/**
 * Returns the full RFC 822 source (headers + body) of the opened email.
 * The per-message access token limits the add-on to the email the user opened.
 */
function getCurrentMessageRaw_(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(e.gmail.messageId);
  return message.getRawContent();
}

// ---------------------------------------------------------------------------
// Talking to the backend
// ---------------------------------------------------------------------------

function analyzeMessage_(rawMessage) {
  var config = getConfig_();

  var messageBytes = Utilities.newBlob(rawMessage).getBytes();
  if (messageBytes.length > MAX_MESSAGE_BYTES) {
    throw new MailGuardError('This email is too large to analyze (limit: 2 MB).');
  }

  var body = JSON.stringify({ raw_message: Utilities.base64EncodeWebSafe(messageBytes) });
  var timestamp = String(Math.floor(Date.now() / 1000));

  var response = UrlFetchApp.fetch(config.backendUrl + '/analyze', {
    method: 'post',
    contentType: 'application/json',
    payload: body,
    headers: {
      'X-MailGuard-Timestamp': timestamp,
      'X-MailGuard-Signature': sign_(config.hmacSecret, timestamp, body),
    },
    muteHttpExceptions: true, // handle error codes ourselves
    followRedirects: false, // never send the email anywhere except the configured backend
  });

  var status = response.getResponseCode();
  console.log('MailGuard: backend responded with HTTP ' + status);
  if (status !== 200) {
    throw new MailGuardError(describeHttpError_(status));
  }

  var data;
  try {
    data = JSON.parse(response.getContentText());
  } catch (parseError) {
    throw new MailGuardError('The MailGuard service returned an unreadable response.');
  }
  return validateResult_(data);
}

function getConfig_() {
  var props = PropertiesService.getScriptProperties();
  var backendUrl = props.getProperty('BACKEND_URL');
  var hmacSecret = props.getProperty('HMAC_SECRET');
  if (!backendUrl || !hmacSecret) {
    throw new MailGuardError('MailGuard is not configured. Set BACKEND_URL and HMAC_SECRET.');
  }
  if (backendUrl.indexOf('https://') !== 0) {
    throw new MailGuardError('MailGuard is misconfigured: BACKEND_URL must use HTTPS.');
  }
  return { backendUrl: backendUrl.replace(/\/+$/, ''), hmacSecret: hmacSecret };
}

/** hex(HMAC_SHA256(secret, timestamp + "." + body)), matching backend/app/security.py. */
function sign_(secret, timestamp, body) {
  var signature = Utilities.computeHmacSha256Signature(
    timestamp + '.' + body,
    secret,
    Utilities.Charset.UTF_8
  );
  return signature
    .map(function (b) {
      return ('0' + (b & 0xff).toString(16)).slice(-2);
    })
    .join('');
}

function describeHttpError_(status) {
  if (status === 401) return 'MailGuard could not authenticate with its service. Check HMAC_SECRET.';
  if (status === 413) return 'This email is too large to analyze.';
  if (status === 422) return 'This email could not be processed.';
  return 'The MailGuard service is unavailable (HTTP ' + status + '). Please try again later.';
}

/** Treat the backend response as untrusted: check every field before using it. */
function validateResult_(data) {
  var valid =
    data &&
    typeof data.score === 'number' &&
    data.score >= 0 &&
    data.score <= 100 &&
    VERDICT_STYLES.hasOwnProperty(data.verdict) &&
    typeof data.summary === 'string' &&
    Array.isArray(data.signals);
  if (!valid) {
    throw new MailGuardError('The MailGuard service returned an unexpected response.');
  }
  var signals = data.signals.filter(function (s) {
    return s && typeof s.title === 'string' && typeof s.points === 'number';
  });
  var limitations = Array.isArray(data.limitations)
    ? data.limitations.filter(function (l) {
        return typeof l === 'string';
      })
    : [];
  return {
    score: Math.round(data.score),
    verdict: data.verdict,
    summary: data.summary,
    signals: signals,
    limitations: limitations,
  };
}

// ---------------------------------------------------------------------------
// Cards (UI)
// ---------------------------------------------------------------------------

function buildResultCard_(result) {
  var style = VERDICT_STYLES[result.verdict];

  var overview = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Verdict')
        .setText('<font color="' + style.color + '"><b>' + style.label + '</b></font>')
    )
    .addWidget(
      CardService.newDecoratedText().setTopLabel('Risk score').setText(result.score + ' / 100')
    )
    .addWidget(CardService.newTextParagraph().setText(escapeHtml_(result.summary)));

  var reasons = CardService.newCardSection().setHeader('Why');
  if (result.signals.length === 0) {
    reasons.addWidget(CardService.newTextParagraph().setText('No risk signals were found.'));
  } else {
    result.signals.forEach(function (signal) {
      var widget = CardService.newDecoratedText()
        .setTopLabel(signal.points > 0 ? '+' + signal.points + ' points' : 'Info')
        .setText(escapeHtml_(signal.title))
        .setWrapText(true);
      if (typeof signal.explanation === 'string') {
        widget.setBottomLabel(escapeHtml_(signal.explanation));
      }
      reasons.addWidget(widget);
    });
  }

  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('MailGuard').setSubtitle('Email risk analysis'))
    .addSection(overview)
    .addSection(reasons);

  if (result.limitations.length > 0) {
    var limits = CardService.newCardSection().setHeader('Limits of this analysis');
    result.limitations.forEach(function (text) {
      limits.addWidget(CardService.newTextParagraph().setText('• ' + escapeHtml_(text)));
    });
    card.addSection(limits);
  }
  return card.build();
}

function buildMessageCard_(text) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('MailGuard'))
    .addSection(CardService.newCardSection().addWidget(CardService.newTextParagraph().setText(escapeHtml_(text))))
    .build();
}

/**
 * Card text supports a small HTML subset. Text derived from emails (via the backend) must be
 * escaped so an attacker cannot inject formatting or links into the verdict card.
 */
function escapeHtml_(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
