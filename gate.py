"""Gate de CI do QSR: falha o build quando ha criptografia vulneravel sem plano.

Regra dura: falta de evidencia vira REFUSED, nunca aprovacao silenciosa.

Duas familias de achado, com regras diferentes:

1. RSA e ECC: dependem da linha do tempo, entao passam pelo criterio de Mosca
   (migracao X + sigilo Y contra a janela ate o computador quantico Z).
2. Hash fraco, TLS/SSL obsoleto e chave privada versionada: quebrados ou expostos
   hoje, sem depender de computador quantico. Nao tem janela para comparar: reprovam
   direto. Antes desta correcao o gate anotava esses achados e aprovava o repositorio.
"""
from __future__ import annotations

import os

# Categorias que reprovam sem passar por Mosca, e o motivo que vai no log e no recibo.
CATEGORIAS_DURAS = {
    "hash_fraco": "MD5/SHA-1 quebrado por ataque classico, sem depender de computador quantico",
    "certificado": "chave privada ou certificado versionado no repositorio",
    "tls_antigo": "protocolo TLS/SSL obsoleto (TLS 1.0/1.1, SSLv2/3)",
}


def main() -> int:
    from quantum_safe_readiness import Ativo, achados_para_ci, scan, selar, veredito_sistema
    from quantum_safe_readiness import resumo_inventario

    caminho = os.environ.get("INPUT_PATH", ".")
    crqc = float(os.environ.get("INPUT_CRQC_YEAR", "2035"))
    x = float(os.environ.get("INPUT_MIGRATION_YEARS", "3"))
    y = float(os.environ.get("INPUT_SECRECY_YEARS", "10"))
    fail_on = os.environ.get("INPUT_FAIL_ON", "not-ready").strip()
    anotar = os.environ.get("INPUT_ANNOTATE", "true").lower() == "true"
    destino = os.environ.get("INPUT_RECEIPT_PATH", "qsr-receipt.json")

    achados = scan(caminho)
    inv = resumo_inventario(achados)
    categorias = inv["por_categoria"]

    # Familia 1: risco dependente do tempo, avaliado por Mosca.
    ativos = []
    if categorias.get("rsa"):
        ativos.append(Ativo("rsa_no_codigo", "RSA-2048", x, y))
    if categorias.get("ecc"):
        ativos.append(Ativo("ecc_no_codigo", "ECDSA", x, y))
    if not ativos:
        ativos = [Ativo("nenhum_uso", "nenhum", 0, 0)]

    risco = veredito_sistema(ativos, crqc)

    # Familia 2: falha direta, sem janela de tempo.
    duros = [
        {"categoria": cat, "ocorrencias": categorias[cat], "motivo": motivo}
        for cat, motivo in CATEGORIAS_DURAS.items()
        if categorias.get(cat)
    ]

    if duros or risco["veredito"] == "0":
        veredito = "0"
    elif risco["veredito"] == "REFUSED":
        veredito = "REFUSED"
    else:
        veredito = "1"

    if anotar:
        for a in achados_para_ci(achados):
            print(f"::error file={a['arquivo']},line={a['linha']},{a['titulo']}::{a['trecho']}")
    for r in risco["ativos"]:
        if r["veredito"] == "0":
            print(f"::error title=Criptografia vulneravel:: {r['ativo']}: {r['motivo']}")
    for d in duros:
        print(f"::error title=Criptografia vulneravel::{d['categoria']}: "
              f"{d['ocorrencias']} ocorrencia(s) - {d['motivo']}")

    rec = selar({"alvo": caminho, "crqc": crqc, "x_anos_migracao": x, "y_anos_sigilo": y,
                 "inventario": inv, "risco": risco, "falhas_diretas": duros,
                 "veredito": veredito,
                 "origem": {"tipo": "github-action", "repo": os.environ.get("GITHUB_REPOSITORY"),
                            "sha": os.environ.get("GITHUB_SHA"), "run": os.environ.get("GITHUB_RUN_ID")}},
                destino)

    print(f"QSR | veredito {veredito} | achados {inv['total']} em {inv['arquivos']} arquivos")
    if duros:
        print("QSR | falhas diretas: " + ", ".join(f"{d['categoria']}={d['ocorrencias']}" for d in duros))
    print(f"QSR | recibo selado em {destino} | selo {rec['sha3_256'][:32]}")
    saida = os.environ.get("GITHUB_OUTPUT")
    if saida:
        with open(saida, "a", encoding="utf-8") as fh:
            fh.write(f"verdict={veredito}\nfindings={inv['total']}\nseal={rec['sha3_256']}\n")

    falha = (veredito == "0") or (veredito == "REFUSED" and fail_on == "not-ready")
    if fail_on == "never":
        falha = False
    return 1 if falha else 0


if __name__ == "__main__":
    raise SystemExit(main())
