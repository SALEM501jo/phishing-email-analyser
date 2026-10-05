using System.Net;

namespace PhishingAnalyser.Api;

/// <summary>
/// The page at "/" - what a visitor (or a recruiter following the link) sees instead of a bare 404. Static text plus
/// the model version; nothing on it comes from a request.
/// </summary>
public static class Landing
{
    public static string Html(string? modelVersion) => $$"""
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Phishing Email Analyser API</title>
        <style>
          :root { color-scheme: light dark; }
          body { font: 16px/1.6 system-ui, sans-serif; max-width: 42rem; margin: 3rem auto; padding: 0 1rem; }
          h1 { font-size: 1.6rem; margin-bottom: .2rem; }
          .muted { opacity: .7; }
          code { background: rgba(127,127,127,.18); padding: .1em .35em; border-radius: 4px; }
          li { margin: .3rem 0; }
        </style>
        </head>
        <body>
        <h1>Phishing Email Analyser</h1>
        <p class="muted">API server &middot; model {{WebUtility.HtmlEncode(modelVersion ?? "rules only")}}</p>
        <p>This server scores an email for phishing and explains the verdict. A Chrome extension sends it the Gmail
        message you have open; it combines a multilingual transformer (English and Arabic) with checks on the sender,
        the links and the attachments.</p>
        <ul>
          <li><a href="https://github.com/SALEM501jo/phishing-email-analyser">Source code, evaluation and honest numbers on GitHub</a></li>
          <li><a href="/health">Health and model version</a> (open)</li>
          <li><code>POST /api/v1/analyse</code> needs a per-install API key</li>
        </ul>
        <p class="muted">The server keeps no email content: it logs only the verdict, the score and counts.</p>
        </body>
        </html>
        """;
}
