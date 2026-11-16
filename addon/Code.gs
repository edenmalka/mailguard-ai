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
  var signals = data.signals
    .filter(function (s) {
      return s && typeof s.title === 'string' && typeof s.points === 'number';
    })
    .map(function (s) {
      return {
        title: s.title,
        points: Math.max(0, Math.round(s.points)),
        category: typeof s.category === 'string' ? s.category : 'other',
        explanation: typeof s.explanation === 'string' ? s.explanation : '',
        evidence: typeof s.evidence === 'string' ? s.evidence : '',
      };
    });
  var patterns = Array.isArray(data.attack_patterns)
    ? data.attack_patterns.filter(function (p) {
        return p && typeof p.name === 'string' && typeof p.description === 'string';
      })
    : [];
  var auth = data.authentication;
  var authentication =
    auth && typeof auth.source === 'string'
      ? {
          source: auth.source,
          reportedBy: typeof auth.reported_by === 'string' ? auth.reported_by : '',
          spf: String(auth.spf),
          dkim: String(auth.dkim),
          dmarc: String(auth.dmarc),
        }
      : null;
  return {
    score: Math.round(data.score),
    verdict: data.verdict,
    summary: data.summary,
    signals: signals,
    limitations: stringsOnly_(data.limitations),
    patterns: patterns,
    recommendation: typeof data.recommendation === 'string' ? data.recommendation : '',
    authentication: authentication,
  };
}

function stringsOnly_(value) {
  return Array.isArray(value)
    ? value.filter(function (v) {
        return typeof v === 'string';
      })
    : [];
}

// ---------------------------------------------------------------------------
// Cards (UI)
// ---------------------------------------------------------------------------

var CATEGORY_LABELS = {
  authentication: 'Sender authentication',
  sender: 'Sender',
  links: 'Links',
  attachments: 'Attachments',
  content: 'Wording',
  structure: 'Message format',
  pattern: 'Attack pattern',
};

function buildResultCard_(result) {
  var style = VERDICT_STYLES[result.verdict];
  var card = CardService.newCardBuilder().setHeader(
    CardService.newCardHeader()
      .setTitle('MailGuard')
      .setSubtitle(style.label + ' · ' + result.score + '/100')
  );

  // 1. Overview: verdict, score bar, recognized attack pattern, summary.
  var overview = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Verdict')
        .setText('<font color="' + style.color + '"><b>' + style.label + '</b></font>')
        .setBottomLabel('Risk score ' + result.score + ' / 100')
    )
    .addWidget(CardService.newTextParagraph().setText(scoreBar_(result.score, style.color)));
  if (result.patterns.length > 0) {
    overview.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Looks like')
        .setText('<b>' + escapeHtml_(result.patterns[0].name) + '</b>')
        .setBottomLabel(escapeHtml_(result.patterns[0].description))
        .setWrapText(true)
    );
  }
  overview.addWidget(CardService.newTextParagraph().setText(escapeHtml_(result.summary)));
  card.addSection(overview);

  // 2. What to do.
  if (result.recommendation) {
    card.addSection(
      CardService.newCardSection()
        .setHeader('What to do')
        .addWidget(CardService.newTextParagraph().setText(escapeHtml_(result.recommendation)))
    );
  }

  // 3. Why: only findings that add points, most significant first.
  var risky = result.signals.filter(function (s) {
    return s.points > 0;
  });
  var why = CardService.newCardSection().setHeader('Why');
  if (risky.length === 0) {
    why.addWidget(CardService.newTextParagraph().setText('No risk signals were found.'));
  }
  risky.forEach(function (signal) {
    why.addWidget(
      CardService.newDecoratedText()
        .setTopLabel('+' + signal.points + ' · ' + categoryLabel_(signal.category))
        .setText(escapeHtml_(signal.title))
        .setBottomLabel(escapeHtml_(signal.explanation))
        .setWrapText(true)
    );
  });
  if (risky.length > 3) {
    why.setCollapsible(true).setNumUncollapsibleWidgets(3);
  }
  card.addSection(why);

  // 4. Sender authentication, labeled as reported by Gmail (not re-checked by MailGuard).
  if (result.authentication) {
    card.addSection(
      CardService.newCardSection()
        .setHeader('Sender authentication')
        .addWidget(authenticationWidget_(result.authentication))
    );
  }

  // 5. Technical details (collapsed): every finding with its evidence.
  if (result.signals.length > 0) {
    var details = CardService.newCardSection()
      .setHeader('Technical details')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(1);
    result.signals.forEach(function (signal) {
      var label = signal.points > 0 ? '+' + signal.points : 'Info';
      var text = '<b>' + escapeHtml_(signal.title) + '</b> (' + label + ')';
      if (signal.evidence) {
        text += '<br>' + escapeHtml_(signal.evidence);
      }
      details.addWidget(CardService.newTextParagraph().setText(text));
    });
    card.addSection(details);
  }

  // 6. Limits of this analysis.
  if (result.limitations.length > 0) {
    var limits = CardService.newCardSection().setHeader('Limits of this analysis');
    result.limitations.forEach(function (text) {
      limits.addWidget(CardService.newTextParagraph().setText('• ' + escapeHtml_(text)));
    });
    card.addSection(limits);
  }

  card.addSection(
    CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText(
        '<font color="#5F6368">MailGuard checks only this message and does not store your emails.</font>'
      )
    )
  );
  return card.build();
}

/** A 10-block bar, filled in the verdict color. */
function scoreBar_(score, color) {
  var filled = Math.round(score / 10);
  return (
    '<font color="' + color + '">' + repeat_('■', filled) + '</font>' +
    '<font color="#DADCE0">' + repeat_('■', 10 - filled) + '</font>'
  );
}

function repeat_(text, count) {
  var out = '';
  for (var i = 0; i < count; i++) out += text;
  return out;
}

function categoryLabel_(category) {
  return CATEGORY_LABELS.hasOwnProperty(category) ? CATEGORY_LABELS[category] : 'Other';
}

function authenticationWidget_(auth) {
  if (auth.source !== 'reported') {
    return CardService.newDecoratedText()
      .setText('Not available')
      .setBottomLabel('Gmail did not provide authentication results for this message.')
      .setWrapText(true);
  }
  return CardService.newDecoratedText()
    .setText(
      'SPF ' + escapeHtml_(auth.spf) + ' · DKIM ' + escapeHtml_(auth.dkim) + ' · DMARC ' + escapeHtml_(auth.dmarc)
    )
    .setBottomLabel('Reported by Gmail (' + escapeHtml_(auth.reportedBy) + '), not re-checked by MailGuard.')
    .setWrapText(true);
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
