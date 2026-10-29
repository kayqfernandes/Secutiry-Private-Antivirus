# Analisador de Segurança Pessoal

Aplicativo local para Windows com interface Tkinter escura. Ele ajuda a revisar arquivos, itens comuns de inicialização e resultados disponíveis do Microsoft Defender. Não substitui um antivírus nem oferece proteção em tempo real.

## Executar a partir do código

Requisitos: Windows 10 ou 11 e Python 3.10 ou superior. No PowerShell, na pasta do projeto:

```powershell
python app.py
```

Para executar a suíte de regressão:

```powershell
python -m unittest -v
```

O aplicativo usa apenas módulos da biblioteca padrão em tempo de execução. O Defender é chamado pelo PowerShell do Windows quando disponível; se a solicitação falhar ou o Defender não estiver disponível, a análise local continua.

## Uso e ações

- **Analisar pasta** examina a pasta escolhida. **Analisar computador** percorre unidades lógicas acessíveis e solicita uma verificação ao Defender. Buscas podem demorar e não conseguem ler todos os arquivos protegidos ou em uso.
- A aba **Armazenamento** lista unidades lógicas montadas, tipo e capacidades. **Analisar selecionados** ou **Analisar todos** envia os volumes ao scanner existente, que examina arquivos de qualquer extensão; os resultados aparecem em **Resultados**. Abrir ou atualizar a aba não inicia análise.
- Na aba **Armazenamento**, dê duplo clique em uma unidade para abrir **Aplicativos instalados**. A lista usa os registros de desinstalação do Windows para mostrar programas instalados naquela unidade, ordenados inicialmente pela estimativa de tamanho do instalador. Ela não percorre os diretórios nem executa aplicativos. A data mostrada é a informada pelo instalador e pode refletir uma atualização, não o último uso. Quando houver histórico local de atividade, a interface indica registros com mais de 180 dias; sem registro, o estado é desconhecido, não “nunca usado”. Esse histórico pode ser incompleto e nenhum programa é removido ou alterado.
- Em **Resultados**, há somente o filtro de classificação. Ele afeta apenas essa lista; não apaga itens nem altera classificações técnicas. Clique nos cabeçalhos para ordenar cada lista.
- As listas de resultados, apps suspeitos, temporários, quarentena e volumes têm rolagem vertical. As tabelas mostram o nome do arquivo para manter as colunas legíveis; o caminho completo aparece nos detalhes do item. A roda atua sobre a lista sob o cursor; seleção e detalhes são mantidos quando a lista é atualizada, desde que o item continue visível.
- Listas grandes são reconstruídas em lotes pequenos para que a janela continue processando eventos e interação durante a atualização.
- Durante a análise, o app impede outra varredura local simultânea. Ao final, o painel e o relatório indicam arquivos inacessíveis/alterados, diretórios ou origens não disponíveis e links/junções ignorados.
- O analisador calcula SHA-256, verifica Authenticode quando possível, sinaliza executáveis e consulta pontos comuns de inicialização. Nunca executa o arquivo analisado.
- As categorias técnicas são `Baixo risco`, `Suspeito`, `Alto risco` e `Inconclusivo`. São sinais para revisão, não prova de que o arquivo seja seguro ou malicioso. A escolha manual `Perigoso` ou `Baixo risco` é apresentada separadamente e não apaga a classificação técnica.
- A lista de temporários reúne candidatos em pastas temporárias conhecidas. Um arquivo temporário ainda pode estar em uso ou ser necessário.
- Em Resultados e Apps perigosos / suspeitos, **Inspecionar código…** mostra scripts e fontes reconhecidos como texto, sem executar seu conteúdo. A leitura é limitada a 1 MiB e destaca padrões heurísticos como execução dinâmica, downloads e inicialização automática. A ausência ou presença desses sinais não confirma que um arquivo seja seguro ou malicioso.
- Excluir, colocar em quarentena, restaurar e remover valores de inicialização exigem confirmação. No Windows, exclusão e movimentação conferem hash e identidade pelo mesmo handle que realiza a ação; o arquivo fica bloqueado contra gravação/substituição enquanto o handle está aberto. Se o Windows não permitir abrir esse handle, a ação falha sem prosseguir. A restauração também verifica o manifesto, o caminho dentro da quarentena e o hash armazenado.
- A quarentena guarda os arquivos em `%LOCALAPPDATA%\PersonalSecurityAnalyzer\Quarantine` com extensão `.quarantined`. É uma movimentação reversível, não criptografia.
- Na remediação de um aplicativo, o Registro é inspecionado apenas nas chaves `Run` documentadas pelo código. A remoção, se confirmada, alcança apenas valores que correspondam ao caminho completo do arquivo; não remove “todos os rastros” nem outros pontos de persistência.

## Privacidade e cobertura

- As análises locais e os relatórios são processados localmente. O registro de auditoria fica em `%LOCALAPPDATA%\PersonalSecurityAnalyzer\audit.jsonl`, mantém até 5 MB e uma rotação anterior. Ele pode conter caminhos completos dos arquivos e pastas analisados.
- A reputação online é opcional e desligada por padrão. Com uma chave VirusTotal informada na sessão, o aplicativo envia somente o SHA-256, nunca o conteúdo do arquivo. O serviço ainda recebe esse hash e pode associá-lo aos seus dados.
- Links simbólicos e pontos de nova análise do Windows são ignorados para impedir que a varredura saia da pasta selecionada.
- Resultados do Defender são filtrados por ID de detecção nova e horário na solicitação atual, mas vêm do dispositivo e não são atribuídos à pasta escolhida. A coincidência temporal não prova que a varredura causou a detecção. Detecções antigas não são apresentadas como novas.
- A verificação de inicialização cobre chaves `Run` comuns e pastas Startup conhecidas, não todas as formas de persistência do Windows. Sem o Defender, heurísticas locais não classificam arquivos como ameaças confirmadas.
- O aplicativo não eleva privilégios, não altera as configurações do Defender e não exclui, move ou altera arquivos automaticamente. Se a auditoria falhar depois de uma ação confirmada, a interface informa a falha de registro separadamente do resultado da ação.

## Organização do código

```text
app.py                              ponto de entrada compatível
resource/                           design visual e componentes da interface
├── __init__.py
└── designer.py                     paleta, botões, painéis, abas e layout
src/security_analyzer/app/          interface e controle de varreduras
src/security_analyzer/core/         modelos, classificação, scanner e inspeção estática de texto
src/security_analyzer/integrations/ Defender, Authenticode, inicialização, reputação, volumes e inventário de apps instalados
src/security_analyzer/remediation/  ações explícitas em arquivos e Registro
src/security_analyzer/storage/      auditoria e relatórios JSON
tests/                              testes unitários e de regressão
.github/workflows/                  testes, build e validação no Windows
scripts/build_windows.ps1            build local com PyInstaller
scripts/smoke_packaged.ps1           teste seguro do executável empacotado
src/security_analyzer/selfcheck.py   verificação em fixture temporária
docs/DISTRIBUICAO-WINDOWS.md        build, assinatura e publicação
```

Os elementos visuais ficam em `resource/designer.py`. A lógica de análise, eventos, auditoria e remediação continua em `src/security_analyzer/`; o designer herda a janela existente e só substitui estilo e layout.

## Build e distribuição Windows

O empacotamento usa PyInstaller em Windows com Python 3.13 e gera uma pasta `onedir`; o Python não precisa estar instalado na máquina que recebe o pacote. O procedimento completo está em [docs/DISTRIBUICAO-WINDOWS.md](docs/DISTRIBUICAO-WINDOWS.md).

O GitHub Actions testa Python 3.10 e 3.13. Depois dos testes, também cria o pacote Windows, inicia o executável com `--self-check` usando somente um arquivo descartável em pasta temporária e gera um ZIP **não assinado** mais seu manifesto SHA-256. Os arquivos ficam disponíveis como artefatos por sete dias. O workflow não publica releases. A distribuição pública exige revisão, assinatura Authenticode com certificado legítimo sob controle do responsável e validação do hash; não coloque chaves privadas no repositório ou no artefato.
