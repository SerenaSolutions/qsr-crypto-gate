# QSR Crypto Gate

GitHub Action que bloqueia o merge quando o repositório usa criptografia vulnerável a
computador quântico, e emite **recibo selado em SHA3-256** para provar o que foi
avaliado, quando e com qual hipótese.

Não é atestado de conformidade. É evidência de prontidão, com o limite escrito no recibo.

## Como funciona

1. Varre arquivos versionados atrás de RSA, ECC, TLS antigo, hash fraco e certificados.
2. Aplica a desigualdade de Mosca: tempo de migração somado ao tempo de sigilo do dado
   contra a janela até o computador quântico relevante.
3. Publica anotação por arquivo e linha no pull request.
4. Falha o build conforme `fail-on`, e grava recibo com selo.

Falta de evidência vira `REFUSED`, nunca aprovação silenciosa.

Duas famílias de achado, com regras diferentes:

1. RSA e ECC: dependem do tempo, então passam pelo critério de Mosca (migração mais
   sigilo contra a janela até o computador quântico).
2. Hash fraco, protocolo TLS obsoleto e chave privada versionada: quebrados ou
   expostos hoje, sem depender de computador quântico. Reprovam direto, sem janela.

Até 21/11/2026 a segunda família só aparecia anotada, e o repositório era aprovado.
O caso está travado por teste em `tests/test_gate.py`.

## Uso

```yaml
name: prontidão pós-quântica
on: [pull_request]
jobs:
  qsr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: SerenaSolutions/qsr-crypto-gate@v1
        with:
          path: '.'
          crqc-year: '2035'
          fail-on: 'not-ready'
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: qsr-receipt
          path: qsr-receipt.json
```

## Entradas

| Entrada | Padrão | O que é |
|---|---|---|
| `path` | `.` | caminho a varrer |
| `crqc-year` | `2035` | ano hipotético do computador quântico relevante (Z) |
| `migration-years` | `3` | anos para migrar o ativo (X) |
| `secrecy-years` | `10` | anos que o dado precisa ficar secreto (Y) |
| `fail-on` | `not-ready` | `vulnerable`, `not-ready` ou `never` |
| `annotate` | `true` | anotar arquivo e linha no PR |
| `receipt-path` | `qsr-receipt.json` | onde gravar o recibo |

## Saídas

`verdict` (1, 0 ou REFUSED), `findings` (número de achados), `seal` (SHA3-256 do recibo).

## Planos

| Plano | Preço | O que inclui |
|---|---|---|
| Community | grátis para repositório público | Action completa, recibo local, sem suporte com prazo |
| Team | US$ 29/mês por organização | repositório privado, até 10 repositórios, resposta em 2 dias úteis |
| Business | US$ 99/mês por organização | repositórios ilimitados, política declarada por ativo, resposta em 1 dia útil |
| Enterprise | a partir de US$ 3.000/mês | SLA de 4 horas, engenheiro nomeado, revisão trimestral dos recibos, assessment anual |

O código da Action é Apache-2.0. O que se paga nos planos pagos é suporte com prazo,
política por ativo e revisão periódica, não o download.

## Base científica

FIPS 203, FIPS 204, FIPS 205, NIST IR 8547 (final, 27/10/2026), NIST SP 800-57,
NSA CNSA 2.0 e NIST SP 1800-38. Detalhes em
[serena-quantum-safe-readiness](https://github.com/SerenaSolutions/serena-quantum-safe-readiness).

Licença Apache-2.0. Autoria institucional: Serena Quantum Solutions.
