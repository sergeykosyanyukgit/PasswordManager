| Команда из корня | Результат |
|---|---|
| `npm.cmd --prefix electron-app ci` | Успешно; установлено 376 пакетов |
| `npm.cmd --prefix electron-app run typecheck` | Успешно |
| `npm.cmd --prefix electron-app test` | 49/49 тестов, 6/6 файлов |
| `npm.cmd --prefix electron-app run build` | Успешно; renderer, main и preload собраны |
| `npm.cmd --prefix electron-app audit` | 0 известных уязвимостей |
| `npm.cmd --prefix electron-app audit --omit=dev` | 0 известных уязвимостей |
| `python -m unittest discover -s scripts -p test_security_check.py` | 15/15 проверок workflow |
| PowerShell AST parser для `scripts/security-check.ps1` | Ошибок синтаксиса нет |

`npm.cmd` использован вместо заблокированного execution policy shim `npm.ps1`.
Первые попытки audit и esbuild в песочнице завершились сетевой ошибкой/Access is denied;
обязательные команды успешно повторены с разрешением вне песочницы.
Предупреждения npm об устаревших пакетах и pending install scripts сохранены как
ограничения окружения; они не были выданы за подтверждённые CVE. Зависимости не менялись.

Тесты и сборка не подтверждают эксплуатационные сценарии Windows/SMB, реальное
исключение захвата экрана или подпись релизного EXE. Portable release, подпись
и Deep Scan перед v1 в этом запуске не выполнялись.

Текущий модульный запуск использовал семь нативных агентов с `fork_turns: none`.
CLI-режим повторного запуска подготовлен и проверен по справке и синтаксису;
повторный платный полный CLI-аудит поверх нативного запуска не выполнялся.

Codex Security Standard завершён: scan ID `454f6a13-6ada-4a03-9199-fbfe003cfcf5`.
[Канонический отчёт](security-check/runs/20260915-audit/codex-security/report.md).
Плагин предупредил: «Working-tree contents changed while the scan was running;
results were saved for the original snapshot». В ходе скана создавались сам workflow
и отчёты. Собственный контроль SHA-256 подтвердил неизменность всех 36 проверенных
файлов приложения и исходных политик; дополнительные источники имеют отдельные хеши.

[Codex Security diff scan самого workflow](security-check/workflow-diff/report.md):
6 файлов, подтверждённых уязвимостей нет. Зафиксирован точный `workflow.patch`.

Измерение плагина (`codex_rollout`, coverage `complete`, 8 threads): totalTokens
13 062 800; inputTokens 12 931 145; cachedInputTokens 12 234 368; outputTokens 131 655.
Это суммарная метрика контекстов/ответов скана, не оценка стоимости.
