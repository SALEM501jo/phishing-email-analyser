using System.Net;

namespace PhishingAnalyser.Api;

/// <summary>
/// The page at "/" - what a visitor (or a recruiter following the link) sees instead of a bare 404. Static text plus
/// the model version; nothing on it comes from a request.
/// </summary>
public static class Landing
{
    public static string Html(string? modelVersion, bool demoEnabled) => $$"""
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Phishing Email Analyser API</title>
        <link rel="stylesheet" href="/site.css">
        </head>
        <body>
        <h1>Phishing Email Analyser</h1>
        <p class="muted">API server &middot; model {{WebUtility.HtmlEncode(modelVersion ?? "rules only")}}</p>
        <p>This server scores an email for phishing and explains the verdict. A Chrome extension sends it the Gmail
        message you have open; it combines a multilingual transformer (English and Arabic) with checks on the sender,
        the links and the attachments.</p>
        {{(demoEnabled ? "<p><a class=\"button\" href=\"/try\">Try it with a sample email</a></p>" : "")}}
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
