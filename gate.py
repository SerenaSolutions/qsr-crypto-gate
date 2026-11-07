"""Gate de CI do QSR: falha o build quando ha criptografia vulneravel sem plano.

Regra dura: falta de evidencia vira REFUSED, nunca aprovacao silenciosa."""
from __future__ import annotations

import json
import os
import sys


def main() -> int:
    from quantum_safe_readiness import Ativo, achados_para_ci, scan, selar, veredito_sistema

    caminho = os.environ.get("INPUT_PATH", ".")
    crqc = float(os.environ.get("INPUT_CRQC_YEAR", "2035"))
    x = float(os.environ.get("INPUT_MIGRATION_YEARS", "3"))
    y = float(os.environ.get("INPUT_SECRECY_YEARS", "10"))
    fail_on = os.environ.get("INPUT_FAIL_ON", "not-ready").strip()
    anotar = os.environ.get("INPUT_ANNOTATE", "true").lower() == "true"
    destino = os.environ.get("INPUT_RECEIPT_PATH", "qsr-receipt.json")

    achados = scan(caminho)
    from quantum_safe_readiness import resumo_inventario
    inv = resumo_inventario(achados)
    ativos = []
    if inv["por_categoria"].get("rsa"):
        ativos.append(Ativo("rsa_no_codigo", "RSA-2048", x, y))
    if inv["por_categoria"].get("ecc"):
        ativos.append(Ativo("ecc_no_codigo", "ECDSA", x, y))
    if not ativos:
        ativos = [Ativo("nenhum_uso", "nenhum", 0, 0)]

    risco = veredito_sistema(ativos, crqc)
    veredito = risco["veredito"]

    if anotar:
        for a in achados_para_ci(achados):
            print(f"::error file={a['arquivo']},line={a['linha']},{a['titulo']}::{a['trecho']}")
    for r in risco["ativos"]:
        if r["veredito"] == "0":
            print(f"::error title=Criptografia vulneravel:: {r['ativo']}: {r['motivo']}")

    rec = selar({"alvo": caminho, "crqc": crqc, "x_anos_migracao": x, "y_anos_sigilo": y,
                 "inventario": inv, "risco": risco, "veredito": veredito,
                 "origem": {"tipo": "github-action", "repo": os.environ.get("GITHUB_REPOSITORY"),
                            "sha": os.environ.get("GITHUB_SHA"), "run": os.environ.get("GITHUB_RUN_ID")}},
                destino)

    print(f"QSR | veredito {veredito} | achados {inv['total']} em {inv['arquivos']} arquivos")
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
