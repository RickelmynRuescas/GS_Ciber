# GS_Ciber

**Memória Digital – Módulo de Cybersecurity** (ambiente fictício) — Global Solution 2026.2, FIAP.

O projeto simula um módulo de proteção de dados pessoais com três blocos:

1. **Parsing de PII** – detecta e mascara CPF, RG, e-mail, telefone, senha e dados de saúde.
2. **Taint Analysis** – marca o dado na entrada (*source*) e bloqueia nas saídas inseguras (*sinks*: log, resposta HTTP, banco).
3. **Tradução via IA** – transforma o evento técnico em um alerta claro para o cidadão (LLM Gemini, com fallback local).

A saída é o `eventos.json` e o `dashboard.html`, com o indicador **Risco Cidadão** (verde / amarelo / vermelho).

## Estrutura

| Arquivo | Descrição |
|---|---|
| `memoria_digital_security.py` | Script principal (parsing, taint analysis, IA, geração do dashboard) |
| `dashboard_template.html` | Molde do dashboard, usado pelo script |
| `dashboard.html` | Dashboard gerado (abre direto no navegador) |
| `eventos.json` | Eventos e achados gerados pela última execução |

## Pré-requisitos

- [Python 3.8+](https://www.python.org/downloads/)
- Um navegador web (Chrome, Edge, Firefox…)
- Nenhuma biblioteca externa: o script usa apenas a biblioteca padrão do Python.

## Como abrir o projeto

### 1. Clonar o repositório

```bash
git clone https://github.com/RickelmynRuescas/GS_Ciber.git
cd GS_Ciber
```

### 2. Executar o módulo

```bash
python memoria_digital_security.py
```

(No Linux/macOS, use `python3` se `python` não funcionar.)

O terminal mostra o passo a passo da demonstração e, ao final, gera/atualiza `eventos.json` e `dashboard.html`.

> Execute o comando dentro da pasta do projeto: o script lê o `dashboard_template.html` do diretório atual.

### 3. Abrir o dashboard

Dê dois cliques em `dashboard.html` ou abra pelo terminal:

```bash
# Windows
start dashboard.html
# macOS
open dashboard.html
# Linux
xdg-open dashboard.html
```

O dashboard não precisa de servidor: é um arquivo HTML estático.

## (Opcional) Usar IA real com Gemini

Sem chave, o sistema usa mensagens de *fallback* prontas. Para usar o LLM, defina a variável de ambiente antes de executar:

```bash
# Windows (PowerShell)
$env:GEMINI_API_KEY = "sua-chave"
python memoria_digital_security.py

# Linux / macOS
export GEMINI_API_KEY="sua-chave"
python3 memoria_digital_security.py
```

Opcionalmente, troque o modelo com `GEMINI_MODEL` (padrão: `gemini-2.5-flash`).

> Nunca coloque a chave diretamente no código nem a envie ao GitHub.
