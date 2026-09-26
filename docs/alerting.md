# Alerting

Event → fingerprint dedup → severity policy → Discord.
HIGH/CRITICAL send immediately; INFO/LOW aggregate into a 5-minute digest (`DiscordBatch`,
flushed by `flush_discord_batches` every 60s). During INITIAL_BASELINE, NEW_* alerts are
SUPPRESSED (persisted, one BASELINE_COMPLETE summary sent instead).
Secrets: findings store full evidence in DB; Discord gets masked preview only.
