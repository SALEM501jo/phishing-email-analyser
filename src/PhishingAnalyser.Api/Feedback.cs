using System.Text.Json;
using Microsoft.Data.Sqlite;
using PhishingAnalyser.Core;

namespace PhishingAnalyser.Api;

public sealed record FeedbackEmail(string? Subject, string? SenderEmail, string? Body, List<LinkDto>? Links);

/// <summary>👍/👎 from the banner. Content is present only if the user explicitly opted in.</summary>
public sealed class FeedbackRequest
{
    public bool Correct { get; init; }
    public string? Verdict { get; init; }
    public double Score { get; init; }
    public string? ModelVersion { get; init; }
    public string? Language { get; init; }
    public List<string>? ReasonCodes { get; init; }
    public double? PhishingProbability { get; init; }
    public FeedbackEmail? Email { get; init; }

    public Dictionary<string, string[]> Validate()
    {
        var errors = new Dictionary<string, string[]>();
        if (Verdict is not (Verdicts.Phishing or Verdicts.Suspicious or Verdicts.Safe))
            errors["verdict"] = ["Verdict must be phishing, suspicious or safe."];
        if (ReasonCodes?.Count > 50 || ReasonCodes?.Any(c => c.Length > 64) == true)
            errors["reasonCodes"] = ["At most 50 codes of up to 64 characters."];
        if (Email?.Body?.Length > 20_000 || Email?.Subject?.Length > 1_000 || Email?.Links?.Count > 50)
            errors["email"] = ["Email too large."];
        return errors;
    }

    /// <summary>
    /// The label this feedback implies, when it's unambiguous: a confirmed verdict keeps its class; a rejected
    /// "phishing" means legitimate and a rejected "safe" means phishing. A rejected "suspicious" says only that it
    /// was wrong, not which way, so it has no label (still counted in the error statistics).
    /// </summary>
    public string? ImpliedLabel() => (Verdict, Correct) switch
    {
        (Verdicts.Phishing, true) => "phishing",
        (Verdicts.Safe, true) => "legitimate",
        (Verdicts.Phishing, false) => "legitimate",
        (Verdicts.Safe, false) => "phishing",
        _ => null,
    };
}

/// <summary>
/// Stores feedback in a small SQLite file (a Docker volume in production). Verdict, codes and model version are
/// enough to track false-positive/negative rates per model version; content rows (opt-in only) become labelled
/// retraining data. Parameterised SQL only.
/// </summary>
public sealed class FeedbackStore
{
    private readonly string _connectionString;

    public FeedbackStore(string databasePath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(databasePath))!);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = databasePath, Mode = SqliteOpenMode.ReadWriteCreate }.ToString();
        using var connection = Open();
        using var create = connection.CreateCommand();
        create.CommandText = """
            CREATE TABLE IF NOT EXISTS feedback (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                received_utc  TEXT    NOT NULL,
                model_version TEXT,
                language      TEXT,
                verdict       TEXT    NOT NULL,
                score         REAL    NOT NULL,
                correct       INTEGER NOT NULL,
                implied_label TEXT,
                reason_codes  TEXT    NOT NULL,
                phishing_prob REAL,
                email_json    TEXT          -- only when the user opted in
            );
            """;
        create.ExecuteNonQuery();
    }

    public void Add(FeedbackRequest f)
    {
        using var connection = Open();
        using var insert = connection.CreateCommand();
        insert.CommandText = """
            INSERT INTO feedback (received_utc, model_version, language, verdict, score, correct, implied_label, reason_codes, phishing_prob, email_json)
            VALUES ($received, $model, $language, $verdict, $score, $correct, $label, $codes, $prob, $email);
            """;
        insert.Parameters.AddWithValue("$received", DateTime.UtcNow.ToString("O"));
        insert.Parameters.AddWithValue("$model", (object?)f.ModelVersion ?? DBNull.Value);
        insert.Parameters.AddWithValue("$language", (object?)f.Language ?? DBNull.Value);
        insert.Parameters.AddWithValue("$verdict", f.Verdict!);
        insert.Parameters.AddWithValue("$score", f.Score);
        insert.Parameters.AddWithValue("$correct", f.Correct ? 1 : 0);
        insert.Parameters.AddWithValue("$label", (object?)f.ImpliedLabel() ?? DBNull.Value);
        insert.Parameters.AddWithValue("$codes", JsonSerializer.Serialize(f.ReasonCodes ?? []));
        insert.Parameters.AddWithValue("$prob", (object?)f.PhishingProbability ?? DBNull.Value);
        insert.Parameters.AddWithValue("$email", f.Email is null ? DBNull.Value : JsonSerializer.Serialize(f.Email));
        insert.ExecuteNonQuery();
    }

    /// <summary>Error rates per verdict - no content, safe to expose to the owner.</summary>
    public IReadOnlyList<object> Summary()
    {
        using var connection = Open();
        using var query = connection.CreateCommand();
        query.CommandText = """
            SELECT verdict, COUNT(*), SUM(correct), SUM(email_json IS NOT NULL)
            FROM feedback GROUP BY verdict ORDER BY verdict;
            """;
        using var reader = query.ExecuteReader();
        var rows = new List<object>();
        while (reader.Read())
        {
            var total = reader.GetInt32(1);
            var correct = reader.GetInt32(2);
            rows.Add(new { verdict = reader.GetString(0), total, correct, wrong = total - correct, withEmail = reader.GetInt32(3) });
        }
        return rows;
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }
}
