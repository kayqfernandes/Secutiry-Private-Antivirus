# Distribuição para Windows

## Build local

O aplicativo usa apenas a biblioteca padrão do Python em tempo de execução. PyInstaller é ferramenta de build, isolada em `requirements-build.txt`.

Use uma instalação de Python 3.13 de 64 bits em Windows e PowerShell:

```powershell
py -3.13 -m venv .venv-build
.\.venv-build\Scripts\Activate.ps1
python -m pip install -r requirements-build.txt
pwsh -File .\scripts\build_windows.ps1
pwsh -File .\scripts\smoke_packaged.ps1
```

O resultado fica em `dist\AnalisadorSegurancaPessoal\`. O smoke test executa o binário com `--self-check`, que analisa apenas um arquivo temporário descartável e retorna um código de saída; não solicita o Defender, não consulta reputação e não acessa arquivos do usuário. Distribua a pasta completa, ou um ZIP dela; não copie apenas o `.exe`, pois os arquivos de suporte também são necessários. O workflow Windows de CI cria um ZIP de validação sem assinatura, seu manifesto SHA-256 e guarda ambos como artefatos por sete dias. Ele não publica releases.

O script de build também detecta distribuições Python que guardam os recursos Tcl/Tk em arquivos ZIP. Nesses casos, extrai os recursos em uma pasta temporária para o PyInstaller coletar a interface gráfica e restaura as variáveis `TCL_LIBRARY` e `TK_LIBRARY` ao terminar.

PyInstaller gera um pacote específico para o sistema e a arquitetura usados no build; um executável Windows deve ser produzido em Windows. O modo `onedir` deixa os componentes visíveis para inspeção e não extrai o programa para uma pasta temporária a cada inicialização. O `.exe` não recebe privilégios elevados e não altera as proteções do Windows.

## Assinatura e publicação

O artefato da CI é **não assinado** e serve apenas para validação. Antes de uma distribuição pública, o responsável pelo projeto deve:

1. Revisar o código e executar a suíte de testes no commit que será distribuído.
2. Construir o pacote em runner Windows limpo e registrar a versão do Python, PyInstaller e commit de origem.
3. Assinar o executável final com um certificado de assinatura de código sob controle do responsável. A chave privada não deve entrar no repositório, no ZIP ou em logs de CI.
4. Usar SHA-256 na assinatura e um serviço de carimbo de tempo RFC 3161 aprovado; validar a assinatura com `signtool verify /pa /v <arquivo.exe>`.
5. Gerar e publicar um hash SHA-256 do ZIP final em canal oficial junto com as instruções de verificação.

Não usar certificado autoassinado como prova de identidade para usuários. Não publique o pacote como assinado até que a assinatura passe na validação do Windows. A assinatura ajuda a confirmar origem e integridade, mas não é uma certificação de que o programa é seguro.

Exemplo para o usuário conferir o ZIP baixado:

```powershell
Get-FileHash .\AnalisadorSegurancaPessoal-win-x64.zip -Algorithm SHA256
```

Compare o valor com o hash publicado pelo projeto. Depois de extrair o pacote, a verificação Authenticode do `.exe` pode ser feita com `signtool verify /pa /v .\AnalisadorSegurancaPessoal\AnalisadorSegurancaPessoal.exe` quando o SDK do Windows estiver instalado.
