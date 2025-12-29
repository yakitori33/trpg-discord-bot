# TRPG Discord Bot (AWS Serverless, Python)

Discord上のTRPG運営で発生する情報散逸/日程調整/状態管理を解消するためのAWSサーバレス構成のMVP実装です。

## 構成

```
trpg-discord-bot/
├── migrations/
│   └── 001_init.sql
├── src/
│   └── trpg_bot/
│       ├── __init__.py
│       ├── config.py
│       ├── db.py
│       ├── discord_api.py
│       ├── embeds.py
│       ├── handler.py
│       ├── routes.py
│       └── repositories.py
├── requirements.txt
├── template.yaml
└── README.md
```

## 主要ファイル

- `src/trpg_bot/handler.py`
  - Discord Interactionsの署名検証 + ルーティング。
- `src/trpg_bot/routes.py`
  - `/setup`, `/scenario`, `/session`, `/poll`, `/complete`, `/nudge` を処理。
- `src/trpg_bot/embeds.py`
  - セッションカード/管制塔パネル/日程集計/シナリオ情報Embedの生成。
- `migrations/001_init.sql`
  - DBスキーマ（PostgreSQL）。

## AWSサーバレス構成 (推奨)

- Discord Interactions Endpoint -> API Gateway (HTTP API) -> Lambda
- Lambda 3秒以内のACK (type=1 or type=4)
- RDS (PostgreSQL)
- EventBridge Scheduler (締切/催促)
- Secrets Manager / SSM (トークン管理)

## デプロイ手順 (SAM)

1. Python依存関係をインストール

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. `template.yaml` を利用してLambdaをビルド

```bash
sam build
```

3. 環境変数を設定してデプロイ

```bash
sam deploy --guided \
  --parameter-overrides \
    DiscordPublicKey=YOUR_DISCORD_PUBLIC_KEY \
    DatabaseUrl=YOUR_POSTGRES_URL \
    DiscordBotToken=YOUR_BOT_TOKEN
```

4. デプロイ後にAPI GatewayのURLをDiscord Developer PortalのInteractions Endpoint URLに設定

## コマンド設計 (例)

- `/setup`
- `/scenario add|edit|info|search|canrun_add|canrun_remove|who_can_gm|who_played`
- `/session create|join|leave`
- `/poll create|avail_input|status|finalize`
- `/complete`
- `/nudge`

## Embeds/UI

- 管制塔パネル: `embeds.ops_panel_embed`
- セッションカード: `embeds.session_card_embed`
- 日程集計: `embeds.availability_summary_embed`
- シナリオ情報: `embeds.scenario_info_embed`

## 注意

- `DISCORD_BOT_TOKEN` が無いとスレッド作成・メッセージ投稿は実行されません。
- 署名検証は `X-Signature-Ed25519` / `X-Signature-Timestamp` を使用。
- 実際のボタン/セレクト/モーダルの設計は `routes.py` に追加可能。
