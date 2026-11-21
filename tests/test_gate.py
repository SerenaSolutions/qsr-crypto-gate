"""Testes do gate. Cada caso monta um alvo temporario e roda gate.py de verdade.

Medido em 21/11/2026: o gate aprovava (veredito 1, exit 0) repositorio com TLSv1.0
e MD5, porque so as categorias rsa e ecc viravam ativo no veredito. Os testes abaixo
travam esse comportamento.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

GATE = Path(__file__).resolve().parents[1] / "gate.py"


def roda(alvo: Path, tmp_path: Path, **extra: str) -> tuple[int, dict]:
    recibo = tmp_path / "recibo.json"
    env = {**os.environ, "INPUT_PATH": str(alvo), "INPUT_RECEIPT_PATH": str(recibo)}
    env.update(extra)
    p = subprocess.run([sys.executable, str(GATE)], env=env, capture_output=True, text=True)
    dados = json.loads(recibo.read_text(encoding="utf-8")) if recibo.exists() else {}
    return p.returncode, dados


def test_repositorio_limpo_aprova(tmp_path: Path) -> None:
    alvo = tmp_path / "limpo"
    alvo.mkdir()
    (alvo / "app.py").write_text("print('ola')\n", encoding="utf-8")
    codigo, recibo = roda(alvo, tmp_path)
    assert codigo == 0
    assert recibo["veredito"] == "1"
    assert recibo["inventario"]["total"] == 0


def test_rsa_reprova(tmp_path: Path) -> None:
    alvo = tmp_path / "com_rsa"
    alvo.mkdir()
    (alvo / "cripto.py").write_text("chave = RSA-2048()\n", encoding="utf-8")
    codigo, recibo = roda(alvo, tmp_path)
    assert recibo["inventario"]["por_categoria"].get("rsa") == 1
    assert codigo == 1
    assert recibo["veredito"] == "0"


def test_tls_antigo_reprova(tmp_path: Path) -> None:
    """Achado de TLSv1.0 tem de reprovar, nao so aparecer anotado."""
    alvo = tmp_path / "com_tls_velho"
    alvo.mkdir()
    (alvo / "nginx.conf").write_text("ssl_protocols TLSv1.0;\n", encoding="utf-8")
    codigo, recibo = roda(alvo, tmp_path)
    assert recibo["inventario"]["por_categoria"].get("tls_antigo") == 1
    assert recibo["veredito"] == "0"
    assert codigo == 1


def test_hash_fraco_reprova(tmp_path: Path) -> None:
    alvo = tmp_path / "com_md5"
    alvo.mkdir()
    (alvo / "legado.py").write_text("hash = MD5(senha)\n", encoding="utf-8")
    codigo, recibo = roda(alvo, tmp_path)
    assert recibo["inventario"]["por_categoria"].get("hash_fraco") == 1
    assert recibo["veredito"] == "0"
    assert codigo == 1


def test_chave_privada_no_repositorio_reprova(tmp_path: Path) -> None:
    alvo = tmp_path / "com_chave"
    alvo.mkdir()
    (alvo / "id_rsa.pem").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n", encoding="utf-8"
    )
    codigo, recibo = roda(alvo, tmp_path)
    assert recibo["inventario"]["por_categoria"].get("certificado") == 1
    assert recibo["veredito"] == "0"
    assert codigo == 1


def test_fail_on_never_nunca_reprova(tmp_path: Path) -> None:
    alvo = tmp_path / "com_rsa"
    alvo.mkdir()
    (alvo / "cripto.py").write_text("chave = RSA-2048()\n", encoding="utf-8")
    codigo, recibo = roda(alvo, tmp_path, INPUT_FAIL_ON="never")
    assert codigo == 0
    assert recibo["veredito"] == "0"
