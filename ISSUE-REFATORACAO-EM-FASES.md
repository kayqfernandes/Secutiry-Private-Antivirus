# Issue: Refatorar o analisador em módulos por fases, sem regressões

## Objetivo

Organizar o MVP em módulos com responsabilidades claras, preservando o comportamento atual durante a refatoração. A separação permitirá corrigir os riscos identificados sem misturar interface, análise e remediação.

## Estrutura proposta

```text
app.py                         ponto de entrada compatível
src/security_analyzer/
├── __main__.py
├── selfcheck.py
├── app/
│   ├── window.py
│   └── controllers.py
├── core/
│   ├── models.py
│   ├── scanner.py
├── integrations/
│   ├── defender.py
│   ├── authenticode.py
│   ├── startup.py
│   ├── drives.py
│   └── reputation.py
├── remediation/
│   ├── quarantine.py
│   ├── file_actions.py
│   └── registry.py
├── storage/
│   ├── audit.py
│   └── reports.py
tests/
├── __init__.py
└── test_analyzer.py            testes unitários/regressão
.github/workflows/              CI Windows
scripts/                        build e smoke test do pacote
```

A interface chamará serviços. Ações de arquivo e Registro não serão feitas diretamente pelos widgets.

## Fases

### Fase 1 — Separar módulos sem mudar comportamento

- [x] Criar o pacote e mover modelos, classificação, varredura, integrações, remediação, auditoria e relatórios para seus módulos.
- [x] Manter `py app.py` como ponto de entrada compatível durante a transição.
- [x] Não alterar critérios de classificação ou comportamento de remediação nesta fase.

### Fase 2 — Corrigir invariantes de segurança

- [x] Separar detecção técnica da decisão manual do usuário. Marcar como “Baixo risco” não pode apagar nem ocultar uma detecção técnica.
- [x] Impedir que links simbólicos e pontos de nova análise do Windows façam a varredura sair da pasta escolhida.
- [x] Validar que a restauração use somente arquivos dentro da pasta de quarentena e conferir o hash antes de restaurar.
- [x] Associar resultados do Defender à verificação atual; não tratar detecções históricas como resultados novos.

Validação desta fase: `py -m unittest -v` (12 testes) e `py -m compileall -q app.py src test_app.py` concluídos sem erros. A correlação do Defender usa detecções novas por ID e horário; isso indica coincidência temporal, não prova causalidade.

### Fase 3 — Testes de regressão no Windows

- [x] Preservar os testes existentes de hash e classificação.
- [x] Adicionar testes para limites de varredura, links, rótulos manuais, quarentena/restauração, Registro e falhas de acesso.
- [x] Usar mocks para Defender e reputação. Testes não iniciam varreduras reais e limitam exclusões a pastas temporárias de teste.
- [x] Executar os testes automaticamente em CI para Windows.

Validação desta fase: 21 testes passaram localmente no Windows. O workflow `Windows regression tests` também executa testes e compilação em Windows com Python 3.10 e 3.13 em pushes e pull requests; a execução remota ocorrerá quando estas alterações forem enviadas ao GitHub.

### Fase 4 — Documentação e distribuição

- [x] Documentar módulos, limites de cobertura, ações de remediação e execução dos testes.
- [x] Definir empacotamento e assinatura do aplicativo depois das fases anteriores.

Entregue: README atualizado; procedimento de build e assinatura em `docs/DISTRIBUICAO-WINDOWS.md`; build reprodutível em `scripts/build_windows.ps1`; PyInstaller isolado em `requirements-build.txt`; CI gera ZIP Windows `onedir` sem assinatura depois dos testes. Não há certificado fornecido, então nenhuma assinatura ou release público foi produzido. O build local depende de instalar a ferramenta; o artifact será produzido pelo workflow ao receber estas alterações.

### Fase 5 — Validar pacote e integridade antes da distribuição

- [x] Adicionar um modo de autoverificação que usa somente um arquivo descartável numa pasta temporária.
- [x] Iniciar o executável empacotado no Windows CI e exigir sucesso em até 60 segundos.
- [x] Gerar e anexar um manifesto SHA-256 ao ZIP de validação.
- [x] Manter assinatura e publicação como etapas bloqueadas até existir certificado legítimo e revisão de release.

Validação local: 22 testes, incluindo a autoverificação, e compilação Python aprovados. Scripts PowerShell aprovados pelo parser. A execução real do binário empacotado ocorre no job Windows do GitHub Actions após as alterações serem enviadas; o artefato permanece sem assinatura e não é release.

## Critérios de aceite

- `py app.py` continua abrindo o aplicativo durante a migração.
- As funcionalidades existentes permanecem disponíveis, salvo mudanças de segurança cobertas por testes.
- Cada fase é entregue em um PR pequeno, com testes passando antes da próxima.
- Nenhum arquivo é executado ou remediado automaticamente. Quarentena, exclusão e alteração do Registro continuam exigindo confirmação explícita.
- Heurísticas continuam sendo apresentadas como sinais para revisão, não como prova de que um arquivo é seguro ou malicioso.

## Fora do escopo

- Implementar proteção em tempo real ou substituir o Microsoft Defender.
- Remover genericamente “todos os rastros” do Windows.
- Mudar ou desativar as proteções do sistema.

## Revisão estática do código — 2026-10-25

Escopo: leitura dos módulos Python, testes, scripts, workflow e documentação. Esta foi uma revisão estática; não executou arquivos analisados, varreduras reais do Defender nem alterações reais no Registro.

### Melhorias encontradas

#### Prioridade alta

1. **[Corrigido na etapa 1] Bloquear remediação sem hash de referência.** Resultados vindos diretamente do Defender são criados sem `sha256`. Antes, `delete_file` e `delete_temp_file` permitiam prosseguir com hash vazio; agora exclusão e quarentena exigem um SHA-256 válido e comparam o conteúdo atual (`src/security_analyzer/remediation/file_actions.py`, `src/security_analyzer/remediation/quarantine.py`).
2. **[Parcialmente corrigido na etapa 1] Excluir do Registro somente valores revisados.** Antes, a interface listava valores e depois reenumerava tudo para remover. Agora guarda e mostra hive/chave/nome/dado revisados, reconsulta cada valor e não remove se dado ou tipo mudaram. Permanece uma janela muito curta entre a reconsulta e `DeleteValue`; a API comum do Registro não faz comparação e exclusão condicional atômica. Avaliar contenção adicional em etapa futura (`src/security_analyzer/app/window.py`, `src/security_analyzer/remediation/registry.py`).
3. **[Parcialmente corrigido na etapa 2; endurecido na etapa 5] Vincular hash, assinatura e remediação à identidade do arquivo.** O scanner guarda identidade/metadata e verifica a estabilidade durante a análise. Exclusão e movimentação no Windows agora validam hash e identidade pelo handle usado na ação, impedindo gravação, substituição ou remoção concorrente enquanto aberto. A verificação Authenticode continua ocorrendo durante a análise, separada da decisão de remediação. A criação de cópias entre volumes e a proteção de diretórios contra troca concorrente ainda dependem de caminhos e da checagem de reparse points; não são uma transação atômica do sistema (`src/security_analyzer/core/scanner.py`, `src/security_analyzer/remediation/locked_file.py`, `src/security_analyzer/remediation/file_actions.py`, `src/security_analyzer/remediation/quarantine.py`).
4. **[Corrigido na etapa 2] Validar toda a rota de restauração contra pontos de nova análise.** A inspeção e a restauração agora percorrem os componentes existentes do destino e rejeitam links/junções antes de criar pastas e antes de mover o arquivo (`src/security_analyzer/remediation/quarantine.py`).
5. **[Corrigido na etapa 2] Não atribuir detecções globais do Defender a uma pasta específica.** A integração consulta detecções novas do dispositivo no período. A interface agora as identifica como globais e não atribuídas à pasta escolhida, e a explicação deixa claro que correlação temporal não prova causalidade (`src/security_analyzer/integrations/defender.py`, `src/security_analyzer/app/window.py`).

#### Prioridade média

6. **Impedir varreduras concorrentes na mesma janela.** Os botões continuam ativos; novas buscas limpam `findings` e reutilizam o mesmo `cancel_event`. Eventos tardios da busca anterior podem misturar resultados ou encerrar o progresso da busca atual. Desabilitar início enquanto houver busca ou associar fila/eventos a um identificador de execução (`src/security_analyzer/app/window.py`, `src/security_analyzer/app/controllers.py`).
7. **Mostrar cobertura parcial.** `os.walk` descarta erros com `onerror=lambda _e:None`, e a leitura da inicialização também ignora várias falhas. O painel não mostra diretórios inacessíveis nem distingue “nenhuma detecção” de “não foi possível verificar”. Contabilizar erros/itens ignorados e incluir os totais no relatório (`src/security_analyzer/core/scanner.py`, `src/security_analyzer/integrations/startup.py`).
8. **Definir política de auditoria e falhas após remediação.** O log cresce sem limite e guarda caminhos completos. Além disso, auditoria é gravada depois de exclusão/quarentena/restauração; se a gravação falhar, a interface pode reportar falha apesar da ação já ter ocorrido. Definir retenção/privacidade e representar separadamente resultado da ação e falha de auditoria (`src/security_analyzer/storage/audit.py`, `src/security_analyzer/app/window.py`).

#### Prioridade baixa

9. **[Parcialmente corrigido na etapa 4] Remover caminhos de código obsoletos e completar testes de integração.** `defender_paths` e `risk_text` foram removidos, os testes foram movidos para `tests/`, e há cobertura simulada para IDs do Defender, falhas de inicialização e concorrência local. Ainda falta validar PowerShell/Defender reais em um ambiente Windows isolado e ampliar casos de integração (`src/security_analyzer/core/scanner.py`, `src/security_analyzer/storage/reports.py`, `tests/`).
10. **Melhorar legibilidade para revisão de segurança.** O mapa acima foi atualizado e os testes organizados. Muitos métodos e instruções continuam compactados em uma linha, dificultando revisão e manutenção. Formatar/refatorar os módulos por partes (`README.md`, módulos Python).

### Fase 6 proposta — Corrigir achados da revisão

- [ ] Resolver primeiro os itens de prioridade alta, com confirmação explícita e testes de regressão para cada condição de corrida e caminho sem hash.
- [ ] Adicionar contadores de cobertura parcial e estados de erro observáveis no painel/relatório.
- [ ] Definir retenção do log e o comportamento quando a auditoria falhar após uma ação de arquivo.
- [ ] Remover código obsoleto, atualizar o mapa da arquitetura e organizar testes por módulo/integração Windows.
- [ ] Executar a suíte e validar o pacote Windows após as correções; não publicar sem assinatura e revisão de release.

#### Etapa 1 — Proteger exclusão, quarentena e confirmação do Registro

- [x] Recusar exclusão/quarentena quando a análise não forneceu hash SHA-256 válido; solicitar nova varredura.
- [x] Recomparar o hash atual com o hash analisado antes de excluir ou mover o arquivo.
- [x] Mostrar os dados exatos dos valores Run revisados e revalidá-los antes de remover; ignorar valores alterados.
- [x] Adicionar regressões para hash ausente, valor do Registro alterado e falha ao excluir valores.

Validação local: 25 testes passaram e `compileall` concluiu sem erros. A revalidação do Registro reduz a janela de mudança, mas não a elimina atomicamente; a identidade do arquivo entre verificação e mutação, o destino por junção e os demais achados de prioridade alta permanecem para etapas seguintes.

#### Etapa 2 — Consistência de arquivos, restauração e escopo do Defender

- [x] Registrar identidade/metadata do arquivo analisado e marcar como inconclusiva uma troca detectada durante hash, assinatura ou consulta.
- [x] Revalidar hash e identidade antes de excluir ou colocar em quarentena; não exportar a identidade interna no relatório.
- [x] Rejeitar reparse points em qualquer componente existente da rota de restauração, inclusive após criar diretórios.
- [x] Exibir detecções do Defender como globais do dispositivo, sem atribuição indevida à pasta selecionada.
- [x] Adicionar testes para identidade alterada durante análise, identidade divergente na exclusão e destino de restauração com ancestral reparse.

Validação local na etapa 2: 28 testes passaram e `compileall` concluiu sem erros. Naquele ponto, ainda restava a janela entre a verificação e a mutação; a etapa 5 abaixo implementa a remediação vinculada ao handle Windows.

#### Etapa 3 — Cobertura parcial, concorrência e auditoria

- [x] Impedir duas varreduras locais simultâneas na mesma janela e reabilitar os controles ao concluir/cancelar.
- [x] Contabilizar arquivos ilegíveis/alterados, diretórios inacessíveis, origens indisponíveis e caminhos ignorados por links ou limite da origem.
- [x] Exibir o resumo de cobertura no painel e incluí-lo no relatório JSON.
- [x] Limitar o log de auditoria a aproximadamente 5 MB mais uma rotação anterior, com trava para gravações concorrentes.
- [x] Tratar falha de auditoria separadamente do resultado da ação e garantir evento de conclusão da busca.
- [x] Adicionar regressões para contagem de falhas, rotação, falha do log e busca simultânea.

Validação local da etapa 3: 34 testes passaram e `compileall` concluiu sem erros. Naquele ponto, erros de inicialização ainda eram ocultos e consultas Defender não tinham IDs; ambos foram tratados na etapa 4 abaixo.

#### Etapa 4 — Relatar fontes e separar execuções do Defender

- [x] Retornar entradas e erros da leitura das chaves Run e pastas Startup, contabilizando falhas no painel/relatório.
- [x] Atribuir um ID distinto a cada solicitação do Defender, incluir o ID na origem/detalhes e evitar duplicar o mesmo DetectionID na sessão.
- [x] Remover o parâmetro `defender_paths` e sua correspondência parcial sem uso do scanner, além do parâmetro `risk_text` não utilizado no relatório.
- [x] Mover a suíte para `tests/test_analyzer.py` e atualizar a descoberta/compilação na CI.
- [x] Adicionar testes para erros simulados de inicialização e IDs de solicitações Defender.

Validação local: 36 testes passaram com `python -m unittest -v`; `compileall` passou para `app.py`, `src` e `tests`. A CI/integração PowerShell real ainda depende da execução remota; os testes locais usam mocks.

#### Etapa 5 — Vincular remediação ao handle do arquivo

- [x] Abrir o arquivo no Windows sem compartilhar acesso de gravação ou exclusão, validar identidade e SHA-256 pelo handle e excluir pelo mesmo handle.
- [x] Vincular movimentação para quarentena e restauração ao handle validado; verificar cópia por SHA-256 em operações entre volumes e reverter cópias incompletas.
- [x] Gravar manifesto de forma atômica e reportar separadamente quando o arquivo foi restaurado, mas o manifesto não pôde ser removido.
- [x] Manter a recusa a links e pontos de nova análise nas rotas, sem executar o conteúdo analisado nem alterar a remediação para modo automático.
- [x] Revalidar exclusão, quarentena e restauração com regressões executadas no Windows.

Validação local: 36 testes passaram no Windows com Python 3.15.1; `compileall` e `app.py --self-check` concluíram com sucesso. O teste de restauração confirmou que a renomeação pelo handle preserva o nome original corretamente. Não houve execução de varredura real do Defender nem teste de movimentação entre volumes distintos; a CI remota ainda depende do envio das alterações ao GitHub. A operação protege o arquivo aberto, mas não torna atômica a escolha dos diretórios de destino nem a comparação/remoção de valores do Registro.
