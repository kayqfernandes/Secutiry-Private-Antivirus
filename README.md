# Analisador de Segurança Pessoal (MVP)

Aplicativo local em Python/Tkinter para Windows. Analisa arquivos sem executá-los, calcula SHA-256 e verifica assinaturas Authenticode quando possível. Não depende do Defender: se ele não estiver disponível, continua com hash, assinatura e sinais heurísticos.

## Executar

PowerShell: `py app.py`. Testes: `py -m unittest -v`.

## Seções

- **Resultados:** motivos, hash, assinatura e reputação opcional. A classificação manual permite marcar `Perigoso` ou `Baixo risco`; o rótulo fica identificado no relatório e não prova que o arquivo seja malicioso ou seguro.
- **Apps perigosos / suspeitos:** aplicativos suspeitos ou que você marcou como perigosos. Você pode deixá-los, movê-los à quarentena reversível ou excluir o arquivo selecionado após confirmação.
- **Candidatos temporários:** procure nas pastas temporárias conhecidas. Um arquivo ali ainda pode ser necessário; escolha deixar, excluir um item ou confirmar a exclusão dos itens listados. Não remove pastas ou chaves do Registro.
- **Quarentena:** arquivos movidos ficam em `%LOCALAPPDATA%\PersonalSecurityAnalyzer\Quarantine`, sem extensão executável, com metadados para restauração. Restaurar não executa o arquivo.

Na exclusão/quarentena de app, uma confirmação separada pode remover somente valores das chaves Run comuns que contenham o caminho completo daquele arquivo. Não há busca genérica por “todos os rastros”; outros pontos de persistência não são alterados.

Toda remediação exige confirmação. Antes de mover/excluir, o hash é conferido novamente. Acesso negado, arquivo em uso ou alterações desde a análise são reportados. O app não eleva privilégios nem reduz proteções. Registros em `%LOCALAPPDATA%\PersonalSecurityAnalyzer\audit.jsonl`.

## Privacidade e limites

VirusTotal é opcional, desligado por padrão; envia apenas hashes mediante chave informada na sessão, nunca o conteúdo. A consulta revela o hash ao serviço. `Baixo risco` não certifica segurança. `Alto risco` só vem de detecções disponíveis do Defender; sem Defender, heurísticas suspeitas são revisão, não certeza. A varredura de inicialização abrange chaves Run comuns e pastas Startup, não todos os pontos de persistência. Buscas completas podem demorar ou não acessar alguns arquivos.
