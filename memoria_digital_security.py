"""
Memória Digital - Módulo de Cybersecurity (mock / ambiente fictício)
Global Solution 2026.2 - FIAP

Três blocos:
  1. Parsing PII    -> detecta e mascara dados sensíveis (CPF, RG, e-mail, telefone, senha, saúde)
  2. Taint Analysis -> marca o dado na entrada (source) e bloqueia nas saídas inseguras (sink)
  3. Tradução via IA -> transforma o evento técnico em alerta claro para o cidadão (LLM + fallback)
Saída: eventos.json + dashboard.html (indicador Risco Cidadão)
"""
import json
import os
import re
import urllib.request
from datetime import datetime

# ---------------------------------------------------------------------------
# 1. PARSING PII
# ---------------------------------------------------------------------------
def cpf_valido(cpf: str) -> bool:
    nums = [int(c) for c in re.sub(r"\D", "", cpf)]
    if len(nums) != 11 or len(set(nums)) == 1:
        return False
    for i in (9, 10):
        soma = sum(n * (i + 1 - idx) for idx, n in enumerate(nums[:i]))
        if (soma * 10 % 11) % 10 != nums[i]:
            return False
    return True


def mascarar_cpf(v: str) -> str:
    d = re.sub(r"\D", "", v)
    return f"***.{d[3:6]}.***-{d[9:]}"


def mascarar_generico(v: str) -> str:
    return v[:2] + "*" * max(len(v) - 2, 3)


def mascarar_email(v: str) -> str:
    user, dom = v.split("@", 1)
    return user[0] + "***@" + dom


def mascarar_tel(v: str) -> str:
    d = re.sub(r"\D", "", v)
    return f"(**) *****-{d[-4:]}"


# (nome, regex, severidade, função de mascaramento, validador opcional)
REGRAS_PII = [
    ("CPF", re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"), "critico", mascarar_cpf, cpf_valido),
    ("RG", re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-?[0-9Xx]\b"), "alto", mascarar_generico, None),
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "medio", mascarar_email, None),
    ("TELEFONE", re.compile(r"\(?\b\d{2}\)?\s?9?\d{4}-?\d{4}\b"), "medio", mascarar_tel, None),
    ("SENHA", re.compile(r"(?i)(?:senha|password|pwd)\s*[:=]\s*(\S+)"), "critico",
     lambda v: "[SENHA-OCULTA]", None),
    ("SAUDE", re.compile(r"(?i)\b(laudo|diagn[oó]stico|CID[- ]?\w?\d+|hiv|diabetes|c[aâ]ncer|depress[aã]o)\b"),
     "critico", lambda v: "[DADO-DE-SAUDE]", None),
]
# nomes de campo que são sensíveis mesmo que o valor não bata com nenhuma regex
CHAVES_SENSIVEIS = {"senha", "password", "pwd", "cpf", "rg", "documento", "laudo", "token"}


def escanear_texto(texto: str, campo: str = "texto"):
    """Retorna (texto_mascarado, lista de achados) para um texto."""
    achados = []
    saida = texto
    for nome, rx, sev, mask, validador in REGRAS_PII:
        for m in rx.finditer(texto):
            bruto = m.group(0)
            if validador and not validador(bruto):
                continue  # evita falso positivo (ex.: número qualquer de 11 dígitos)
            if nome == "SENHA":
                saida = saida.replace(bruto, "senha: [SENHA-OCULTA]")
            elif nome == "SAUDE":
                saida = "[DADO-DE-SAUDE]"  # informação clínica: oculta o campo inteiro
            else:
                saida = saida.replace(bruto, mask(bruto))
            if any(a["campo"] == campo and a["tipo"] == nome for a in achados):
                continue  # um achado por tipo/campo
            alvo = m.group(1) if nome == "SENHA" else bruto
            achados.append({"campo": campo, "tipo": nome, "severidade": sev,
                            "valor_mascarado": mask(alvo)})
    return saida, achados


def mascarar_estrutura(obj, chave=""):
    """Devolve cópia do dict/lista/str com todo PII mascarado (inclusive por nome de chave)."""
    if isinstance(obj, dict):
        return {k: mascarar_estrutura(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mascarar_estrutura(v, chave) for v in obj]
    if isinstance(obj, str):
        masc, achados = escanear_texto(str(obj))
        if chave.lower() in CHAVES_SENSIVEIS and not achados:
            return "[OCULTO]"
        return masc
    return obj


# ---------------------------------------------------------------------------
# 2. TAINT ANALYSIS (source -> propagação -> sink)
# ---------------------------------------------------------------------------
class Tainted(str):
    """String marcada como contaminada (contém PII). A marca se propaga em + e upper()."""
    origem = "desconhecida"

    def __new__(cls, valor, origem="payload"):
        obj = super().__new__(cls, valor)
        obj.origem = origem
        return obj

    def __add__(self, other):
        return Tainted(str(self) + str(other), self.origem)

    def __radd__(self, other):
        return Tainted(str(other) + str(self), self.origem)

    def upper(self):
        return Tainted(super().upper(), self.origem)


EVENTOS = []
BANCO = []  # "banco de dados" fictício (só recebe dados já mascarados)


def registrar_evento(sink, tipo, severidade, detalhe):
    EVENTOS.append({
        "hora": datetime.now().strftime("%H:%M:%S"),
        "sink": sink, "tipo": tipo, "severidade": severidade, "detalhe": detalhe,
    })


def entrada_source(payload: dict):
    """SOURCE: toda requisição entra aqui. Marca como Tainted o que tem PII e gera cópia mascarada.
    Retorna (payload_contaminado, payload_seguro, achados)."""
    achados = []

    def visitar(obj, caminho=""):
        if isinstance(obj, dict):
            return {k: visitar(v, f"{caminho}.{k}" if caminho else k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [visitar(v, f"{caminho}[{i}]") for i, v in enumerate(obj)]
        if isinstance(obj, str):
            chave = caminho.split(".")[-1].lower()
            _, ach = escanear_texto(obj, caminho)
            if not ach and chave in CHAVES_SENSIVEIS:
                ach = [{"campo": caminho, "tipo": "CHAVE_SENSIVEL", "severidade": "alto",
                        "valor_mascarado": "[OCULTO]"}]
            if ach:
                achados.extend(ach)
                return Tainted(obj, origem=caminho)
        return obj

    contaminado = visitar(payload)
    seguro = mascarar_estrutura(payload)
    return contaminado, seguro, achados


def _contaminado(obj, chave="") -> bool:
    """True se o valor (ou algo dentro dele) está marcado como Tainted, tem PII em claro
    ou está em um campo de nome sensível."""
    if isinstance(obj, Tainted):
        return True
    if isinstance(obj, dict):
        return any(_contaminado(v, k) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_contaminado(v, chave) for v in obj)
    if isinstance(obj, str):
        return bool(escanear_texto(obj)[1]) or chave.lower() in CHAVES_SENSIVEIS
    return False


class SafeLogger:
    """SINK de log: bloqueia valor Tainted ou com PII em texto claro (segunda camada, via regex)."""
    def info(self, mensagem, contexto="log"):
        if _contaminado(mensagem):
            registrar_evento(contexto, "Vazamento de PII bloqueado", "alto",
                             "Tentativa de gravar dado sensível em log de sistema")
            print("[SafeLogger] BLOQUEADO -> dado sensível não foi gravado no log")
            return False
        print(f"[LOG] {mensagem}")
        return True


def resposta_http(dados, autenticado: bool):
    """SINK de resposta HTTP: sem autenticação, bloqueia se houver PII; autenticada, só envia mascarado."""
    if autenticado:
        return {"status": 200, "dados": mascarar_estrutura(dados)}
    if _contaminado(dados):
        registrar_evento("resposta_http", "Vazamento de PII em resposta pública bloqueado", "critico",
                         "Resposta HTTP sem autenticação continha dado sensível")
        return {"status": 403, "erro": "Taint Sink Blocked"}
    return {"status": 200, "dados": dados}


def salvar_banco(registro: dict):
    """SINK de banco: grava somente a versão mascarada do registro."""
    mascarado = mascarar_estrutura(registro)
    if _contaminado(registro):
        registrar_evento("banco", "PII mascarado antes da gravação", "medio",
                         "Registro continha dado sensível; gravado apenas mascarado")
    BANCO.append(mascarado)
    return mascarado


# ---------------------------------------------------------------------------
# 3. TRADUÇÃO VIA IA (LLM + fallback)
# ---------------------------------------------------------------------------
FALLBACK = {
    "log": "Alguém quase gravou seus dados pessoais em um registro interno, mas nosso sistema impediu. Seus dados continuam protegidos.",
    "resposta_http": "Houve uma tentativa de mostrar seus dados para quem não estava autorizado, mas o sistema bloqueou. Nada foi exposto.",
    "banco": "Seus dados sensíveis foram escondidos antes de serem guardados. Assim, ninguém consegue ler seu CPF ou senha por engano.",
}


def prompt_para_llm(evento: dict) -> str:
    # O prompt leva só o tipo do evento, nunca o dado sensível em si.
    return (f"Traduza a falha técnica '{evento['tipo']}' (saída: {evento['sink']}, "
            f"severidade: {evento['severidade']}) para um cidadão leigo de 60 anos, em 2 frases, "
            "sem termos técnicos, dizendo se ele precisa fazer algo.")


def traduzir_via_ia(evento: dict) -> dict:
    prompt = prompt_para_llm(evento)
    chave = os.getenv("GEMINI_API_KEY")
    if chave:
        try:
            modelo = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{modelo}:generateContent"
            corpo = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode()
            req = urllib.request.Request(url, corpo, {"Content-Type": "application/json",
                                                      "x-goog-api-key": chave})
            with urllib.request.urlopen(req, timeout=15) as r:
                texto = json.load(r)["candidates"][0]["content"]["parts"][0]["text"].strip()
            return {"mensagem": texto, "fonte": f"LLM ({modelo})", "prompt": prompt}
        except Exception as e:  # rede/chave inválida: não derruba o sistema
            print(f"[IA] falha no LLM ({e}); usando fallback")
    return {"mensagem": FALLBACK.get(evento["sink"].split(" ")[0],
                                     "Bloqueamos uma ação para proteger sua privacidade."),
            "fonte": "Fallback (sem chave de LLM)", "prompt": prompt}


# ---------------------------------------------------------------------------
# RISCO CIDADÃO (farol)
# ---------------------------------------------------------------------------
def risco_cidadao(eventos: list) -> dict:
    n = len(eventos)
    critico = any(e["severidade"] == "critico" for e in eventos)
    if n == 0:
        return {"nivel": "verde", "rotulo": "Seguro", "regra": "0 eventos"}
    if n >= 3 or critico:
        return {"nivel": "vermelho", "rotulo": "Risco alto", "regra": "3+ eventos ou evento crítico"}
    return {"nivel": "amarelo", "rotulo": "Atenção", "regra": "1-2 eventos sem criticidade"}


# ---------------------------------------------------------------------------
# DEMONSTRAÇÃO (cenário fictício da Memória Digital)
# ---------------------------------------------------------------------------
def main():
    print("=" * 64)
    print("MEMÓRIA DIGITAL - Módulo de Cybersecurity (ambiente fictício)")
    print("=" * 64)
    logger = SafeLogger()

    payload = {
        "usuario": "Maria Souza",
        "mensagem_suspeita": ("Olá, aqui é do banco. Confirme seu CPF 529.982.247-25 e "
                              "senha: 123456 para evitar bloqueio. Ligue (11) 98765-4321."),
        "contato": "maria.souza@email.com",
        "documento": "529.982.247-25",
        "rg": "12.345.678-9",
        "senha": "Mudar@123",
        "observacao_saude": "Laudo médico: diabetes tipo 2",
        "numero_aleatorio": "12345678900",  # 11 dígitos, mas CPF inválido -> não deve ser PII
    }

    print("\n--- 1) SOURCE: payload recebido e escaneado ---")
    contaminado, seguro, achados = entrada_source(payload)
    for a in achados:
        print(f"  [PII] campo={a['campo']:<20} tipo={a['tipo']:<15} sev={a['severidade']:<8} -> {a['valor_mascarado']}")
    print("\n  Versão segura (pode ir ao banco):")
    print("  " + json.dumps(seguro, ensure_ascii=False, indent=2).replace("\n", "\n  "))

    print("\n--- 2) SINKS: tentativas de vazamento ---")
    print("> logger.info(documento contaminado)")
    logger.info(contaminado["documento"])
    print("> logger.info(mensagem sem PII)")
    logger.info("Análise concluída para o usuário")
    print("> logger.info(senha)  # valor sem padrão detectável por regex: só a marca de taint bloqueia")
    logger.info(contaminado["senha"], contexto="log (senha)")
    print("> propagação: 'CPF: ' + documento")
    propagado = "CPF: " + contaminado["documento"]
    print(f"  tipo do resultado = {type(propagado).__name__} (marca preservada)")
    logger.info(propagado, contexto="log (propagação)")
    print("> resposta HTTP pública com PII")
    print("  ", resposta_http({"cpf": contaminado["documento"]}, autenticado=False))
    print("> resposta HTTP autenticada (mesmo dado, sai mascarado)")
    print("  ", resposta_http({"cpf": contaminado["documento"]}, autenticado=True))
    print("> gravação no banco (registro original entra, só o mascarado é gravado)")
    gravado = salvar_banco(payload)
    print("  ", json.dumps(gravado, ensure_ascii=False))

    print("\n--- 3) IA: tradução dos eventos para o cidadão ---")
    for ev in EVENTOS:
        r = traduzir_via_ia(ev)
        ev["mensagem_cidadao"] = r["mensagem"]
        ev["fonte_mensagem"] = r["fonte"]
        ev["prompt"] = r["prompt"]
        print(f"  [{ev['sink']}] ({r['fonte']})\n    {r['mensagem']}")

    risco = risco_cidadao(EVENTOS)
    print(f"\n--- RISCO CIDADÃO: {risco['nivel'].upper()} ({risco['rotulo']}) | regra: {risco['regra']}")

    dados = {"risco": risco, "eventos": EVENTOS, "achados": achados,
             "gerado_em": datetime.now().strftime("%d/%m/%Y %H:%M")}
    with open("eventos.json", "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)
    gerar_dashboard(dados)
    print("\nArquivos gerados: eventos.json, dashboard.html")


def gerar_dashboard(dados: dict, caminho="dashboard.html"):
    with open("dashboard_template.html", encoding="utf-8") as f:
        molde = f.read()
    # "</" escapado: evita que um texto vindo do LLM feche a tag <script> da página
    js = json.dumps(dados, ensure_ascii=False).replace("</", "<\\/")
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(molde.replace("__DADOS__", js))


if __name__ == "__main__":
    main()
