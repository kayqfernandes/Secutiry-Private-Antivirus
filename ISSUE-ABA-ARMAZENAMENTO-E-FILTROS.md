# Issue: Aba de armazenamento, varredura por volume e filtros de arquivos

## Objetivo

Adicionar uma aba **Armazenamento** que mostre os volumes/discos montados no Windows e permita analisar todos os arquivos acessíveis de um disco escolhido ou de todos os discos. A lista deve permitir localizar arquivos por tamanho e outros critérios, com rolagem clara e independente para não perder a posição.

## Escopo funcional

- [x] Listar volumes Windows acessíveis com letra/rótulo, tipo de unidade e capacidade total/livre, atualizando a lista sob solicitação.
- [x] Permitir selecionar um ou mais volumes e iniciar uma varredura; oferecer também **Analisar todos**. Não iniciar varredura completa apenas por abrir a aba.
- [x] Incluir arquivos de qualquer extensão, não somente executáveis. Mostrar tamanho, caminho, extensão/tipo, SHA-256 disponível, classificação técnica e estado da assinatura quando aplicável.
- [x] Exibir progresso, botão de cancelamento e resumo de cobertura. Relatar arquivos/pastas inacessíveis, volumes indisponíveis, arquivos alterados e itens pulados.
- [x] Adicionar filtros locais aos resultados, restritos à classificação de risco.
- [x] Permitir ordenar por nome/caminho, tamanho, tipo e classificação. Filtros e ordenação não devem iniciar uma nova análise nem alterar a classificação técnica.
- [x] Adicionar barras de rolagem verticais às listas de Resultados, Apps perigosos / suspeitos, Candidatos temporários, Quarentena e à nova lista de armazenamento. A rolagem por roda do mouse deve atuar na lista sob o ponteiro e preservar a posição ao atualizar detalhes ou filtros.
- [x] Manter seleção, painel de detalhes e ações explícitas existentes funcionando com os itens filtrados.

## Requisitos de segurança e privacidade

- Nunca executar arquivos durante a varredura ou inspeção.
- Não excluir, mover, alterar ou colocar arquivos em quarentena automaticamente. Remediação permanece sujeita às confirmações já existentes.
- Não desativar nem reduzir proteções do Windows ou do Defender.
- Respeitar as permissões do usuário e os limites de cobertura: itens inacessíveis ou pulados devem aparecer como cobertura parcial, nunca como resultado limpo.
- Ignorar links simbólicos e pontos de nova análise conforme as regras existentes do scanner.
- Não acrescentar consultas de rede. A reputação continua opcional, desligada por padrão e limitada ao envio de hashes conforme a implementação atual.
- Apresentar classificações e heurísticas como sinais para revisão, nunca como prova de segurança ou malware.

## Implementação por fases

### Fase 1 — Inventário de volumes e experiência da aba

- [x] Definir o modelo da linha de volume e enumerar discos/volumes montados sem iniciar varreduras.
- [x] Criar a aba, seleção de volumes, capacidade e estados indisponível/removível.
- [x] Integrar a navegação e o layout sem alterar as abas nem ações atuais.

Entregue: `VolumeInfo` e `enumerate_volumes()` listam unidades lógicas montadas, tipo, rótulo, capacidade, espaço livre e indisponibilidade; `drives()` continua mantendo sua API anterior. A aba **Armazenamento** lista volumes e permite seleção múltipla, atualização manual e detalhes. A abertura/atualização enumera volumes, mas não percorre arquivos.

Validação local: 40 testes passaram, incluindo enumeração simulada com unidade fixa, removível e inacessível; `compileall` e `app.py --self-check` passaram. A montagem da aba foi verificada com volumes simulados. Não foi iniciada varredura real de discos.

### Fase 2 — Varredura por volume

- [x] Reutilizar o scanner existente para um ou mais volumes, incluindo arquivos de qualquer extensão.
- [x] Manter execução em thread, progresso, cancelamento, limites de origem e resumo de cobertura.
- [x] Evitar execuções concorrentes e associar eventos/resultados à solicitação correta.

Entregue: a aba **Armazenamento** agora oferece **Analisar selecionados** e **Analisar todos**. Os dois caminhos passam as raízes escolhidas ao scanner existente; ele percorre arquivos sem filtrar por extensão e publica os resultados em **Resultados**. A análise roda em thread, pode ser cancelada e mantém contadores de cobertura. Cada execução local recebe um ID; eventos tardios de outra execução são ignorados. Solicitações Defender iniciadas por uma varredura também carregam esse ID, além do ID próprio da solicitação.

Validação local: 45 testes passaram, incluindo múltiplas raízes, extensões distintas, eventos de execução antiga e correlação dos eventos da mesma execução. `compileall` e `app.py --self-check` passaram. A interface foi verificada usando volumes simulados; nenhum disco real foi varrido.

### Fase 3 — Filtros, ordenação e rolagem

- [x] Implementar filtros combináveis sem descartar resultados da análise nem recalcular risco.
- [x] Acrescentar ordenação e barras de rolagem vertical em todas as listas.
- [x] Manter seleção e detalhe coerentes quando filtros ou abas mudarem.

Entregue: a aba **Resultados** tem somente um filtro de classificação, aplicado exclusivamente à lista dessa aba. Ele não altera classificações técnicas nem remove achados. Os cabeçalhos das tabelas ordenam os itens, e novos resultados respeitam a ordenação ativa. As tabelas mostram nomes de arquivos; os detalhes continuam exibindo caminhos completos. Resultados, apps perigosos/suspeitos, candidatos temporários, quarentena e volumes têm rolagem vertical; a roda atua na lista sob o cursor. Atualizações preservam posição e seleção quando possível e limpam detalhes quando o item deixa de estar visível. A reconstrução de listas grandes ocorre em lotes de 250 itens para permitir que a janela continue atendendo à fila de eventos e à interação.

Validação: validação automatizada de filtros, ordenação, rolagem e seleção fica para a Fase 4. Nenhum disco real foi analisado nesta fase.

### Fase 4 — Regressão, documentação e validação

- [x] Testar enumeração usando mocks/fixtures, filtros, ordenação, cancelamento, cobertura parcial e associação de seleção.
- [x] Testar a lógica em diretórios temporários; não varrer discos reais nem executar arquivos na CI.
- [x] Atualizar documentação e executar a suíte Windows e a validação de pacote.
- [x] Revisar desempenho com grande volume de resultados e garantir que a interface continue responsiva.

Validação da Fase 4: 53 testes passaram no Windows com Python 3.15.1; também passaram `compileall` e `app.py --self-check`. O teste do executável empacotado passou após corrigir a coleta de Tcl/Tk para instalações Python que armazenam esses recursos em ZIP. A reconstrução das listas foi limitada a lotes de 250 linhas e coberta por teste com 501 resultados sintéticos. Não foram analisados discos reais nem executados arquivos. A matriz CI configurada para Python 3.10 e 3.13 não foi executada localmente.

Revisão visual posterior: os filtros foram reduzidos ao seletor de classificação; as tabelas passaram a exibir nomes dos arquivos com caminhos completos nos detalhes, e as colunas da lista de volumes foram configuradas para ocupar o espaço disponível. A suíte não foi reexecutada após essa revisão.

## Critérios de aceite

- O usuário vê os volumes detectados e escolhe explicitamente quais analisar.
- A análise inclui arquivos de dados e código de qualquer extensão, sem executar nenhum deles.
- O usuário consegue filtrar por classificação e ordenar por tamanho, tipo, risco e caminho/nome.
- Todas as listas longas têm rolagem vertical utilizável, inclusive por roda do mouse.
- Cancelar encerra a varredura sem congelar a interface; cobertura incompleta fica explícita.
- Abas, seleção, detalhes, auditoria, reputação opcional, Defender, quarentena e confirmações atuais continuam funcionando.
- Nenhuma ação de remediação é automática e nenhuma proteção do Windows é reduzida.

## Fora do escopo

- Prometer detecção ou certeza absoluta de que arquivos são seguros ou maliciosos.
- Executar, descompactar ou interpretar código analisado.
- Fazer varredura em nível de kernel, contornar permissões ou substituir o Microsoft Defender.
- Upload do conteúdo dos arquivos ou consulta online automática.

## Status da criação

- Issue do GitHub não criada: a integração conectada retornou HTTP 403 (`Resource not accessible by integration`).
- Esta especificação local foi criada para manter o plano disponível no workspace.

## Extensão posterior — inventário de aplicativos por unidade

- [x] Abrir uma aba de aplicativos instalados ao dar duplo clique em um volume disponível.
- [x] Listar somente programas registrados pelo Windows com local de instalação dentro da unidade escolhida; exibir primeiro os maiores conforme a estimativa registrada pelo instalador.
- [x] Mostrar atividade local registrada quando disponível e distinguir “sem registro” de inatividade confirmada.
- [x] Manter inventário somente de leitura: sem percorrer arquivos, iniciar aplicativos ou oferecer remoção.

Entregue localmente: a aba **Aplicativos instalados** mostra nome, publicador, tamanho estimado, data informada pelo instalador e atividade local. A marca “Mais de 180 dias” significa que o histórico local contém um registro antigo; não prova que o aplicativo esteja sem uso. Itens sem registro ficam como desconhecidos. Componentes marcados pelo Windows como componentes de sistema/atualizações e entradas em locais de sistema são omitidos, mas a lista continua sujeita à qualidade dos metadados dos instaladores. O inventário não faz recomendações de desinstalação.

Limitação importante: o valor `InstallDate` do Windows Installer corresponde à data da última manutenção do produto e pode ser atualizado por reparos/atualizações; por isso é exibido separado da atividade de uso. Consulte a [documentação da Microsoft sobre a chave Uninstall](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key).
