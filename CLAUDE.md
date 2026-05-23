# CLAUDE.md — ATF プロジェクト

## このプロジェクトは何か

`agent-trust-fabric` (ATF) — 異なる開発者・異なるベンダーが作った AI エージェント
同士が、安全に発見・委任・検証・監査を行うための、中立 OSS substrate。

詳細は [`README.md`](./README.md) と [`docs/specs/2026-05-23-atf-design.md`](./docs/specs/2026-05-23-atf-design.md) を読む。

## セッション開始時に読むもの

1. `README.md` — プロダクト概要
2. `docs/specs/2026-05-23-atf-design.md` — 設計の source of truth
3. `decisions/0001-design-criteria.md` — 判断基準（trade-off の優先順位）
4. `decisions/` 内の他の ADR — 重い判断の履歴

## 判断に迷ったら

[ADR-0001](./decisions/0001-design-criteria.md) の 8 つの判断基準を必ず参照。
迷う前にそこを読む。新しい trade-off に直面したら、その判断基準のどれを根拠に
したかを示してから決定する。

## 作業作法

- **設計書の更新は必ず差分提示 → 確認 → 適用**。設計書は仕様の source of truth。
- **コード変更は仕様変更を伴うものか確認**。仕様変更を伴う場合は ADR を先に書く。
- **コミット・push は人間の明示的許可がない限り行わない**。
- **`spec/` 以下の RFC 風ドキュメントは特に厳格**。breaking change は ADR 必須。

## エンジニアリング・スキル

このプロジェクトのコード作業時は、親 `Claude/CLAUDE.md` の Agent Skills Protocol
を継承する。`.agent-skills/` の以下を順に適用：

1. `spec.md` — 仕様明確化
2. `plan.md` — タスク分解
3. `build.md` — 段階的実装
4. `test.md` — TDD
5. `review.md` — コードレビュー
6. `security.md` — ATF はセキュリティ製品なので特に重要

## 進捗管理

- **TaskCreate / TaskList** で当セッションのタスクを管理
- **decisions-log.md**（後日作成）に試行錯誤を時系列で残す
- **decisions/** に重い判断を ADR として残す

## してはいけないこと

- 中央 server を前提とした設計（Federation 純度を壊す）
- 単一ベンダー特化機能（Vendor 中立性を壊す）
- 設計書から外れた実装（仕様変更なら設計書を先に更新）
- セキュリティ機能の opt-out 化（基準 6 違反）
- breaking change を 2 minor 後方互換せずに入れる（基準 7 違反）
