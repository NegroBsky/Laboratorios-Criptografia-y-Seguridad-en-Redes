"""
Programa de cifrado y descifrado con AES, DES y 3DES
Cifra el mismo texto con los 3 algoritmos usando la misma key e IV base.
Uso: python3 cifrado.py
"""

import base64
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes

# ─────────────────────────────────────────────
# Tamaños requeridos por algoritmo (en bytes)
# ─────────────────────────────────────────────
ALGO_CONFIG = {
    "AES":  {"key_sizes": [16, 24, 32], "iv_size": 16, "default_key": 32},
    "DES":  {"key_sizes": [8],          "iv_size": 8,  "default_key": 8},
    "3DES": {"key_sizes": [16, 24],     "iv_size": 8,  "default_key": 16},
}


# ─────────────────────────────────────────────
# Utilidades
# ─────────────────────────────────────────────

def ajustar_bytes(data: bytes, objetivo: int, nombre: str) -> tuple[bytes, str]:
    """Ajusta data al tamaño objetivo. Retorna (bytes_ajustados, accion)."""
    largo = len(data)
    if largo < objetivo:
        extra = get_random_bytes(objetivo - largo)
        return data + extra, f"COMPLETADO (+{objetivo - largo}B aleatorios)"
    elif largo > objetivo:
        return data[:objetivo], f"TRUNCADO a {objetivo}B"
    else:
        return data, "Sin cambios (tamaño exacto)"


def ajustar_clave(clave_raw: bytes, algo: str) -> bytes:
    sizes  = ALGO_CONFIG[algo]["key_sizes"]
    largo  = len(clave_raw)
    objetivo = next((s for s in sorted(sizes) if largo <= s), max(sizes))
    clave, accion = ajustar_bytes(clave_raw, objetivo, "Clave")
    print(f"    Tamaño recibido  : {largo}B  →  objetivo: {objetivo}B")
    print(f"    Acción           : {accion}")
    print(f"    Clave final(hex) : {clave.hex()}")
    print(f"    Clave final(b64) : {base64.b64encode(clave).decode()}")
    return clave


def ajustar_iv(iv_raw: bytes, algo: str) -> bytes:
    iv_size = ALGO_CONFIG[algo]["iv_size"]
    largo   = len(iv_raw)
    iv, accion = ajustar_bytes(iv_raw, iv_size, "IV")
    print(f"    Tamaño recibido  : {largo}B  →  requerido: {iv_size}B")
    print(f"    Acción           : {accion}")
    print(f"    IV final(hex)    : {iv.hex()}")
    return iv


def pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    return data[:-data[-1]]


# ─────────────────────────────────────────────
# Funciones de cifrado / descifrado
# ─────────────────────────────────────────────

def cifrar_aes(texto, clave, iv):
    c = AES.new(clave, AES.MODE_CBC, iv)
    return c.encrypt(pad(texto, AES.block_size))

def descifrar_aes(cifrado, clave, iv):
    c = AES.new(clave, AES.MODE_CBC, iv)
    return unpad(c.decrypt(cifrado))

def cifrar_des(texto, clave, iv):
    c = DES.new(clave, DES.MODE_CBC, iv)
    return c.encrypt(pad(texto, DES.block_size))

def descifrar_des(cifrado, clave, iv):
    c = DES.new(clave, DES.MODE_CBC, iv)
    return unpad(c.decrypt(cifrado))

def cifrar_3des(texto, clave, iv):
    c = DES3.new(clave, DES3.MODE_CBC, iv)
    return c.encrypt(pad(texto, DES3.block_size))

def descifrar_3des(cifrado, clave, iv):
    c = DES3.new(clave, DES3.MODE_CBC, iv)
    return unpad(c.decrypt(cifrado))

CIFRADORES = {
    "AES":  (cifrar_aes,  descifrar_aes),
    "DES":  (cifrar_des,  descifrar_des),
    "3DES": (cifrar_3des, descifrar_3des),
}


# ─────────────────────────────────────────────
# SECCIÓN 1 — Solicitud de datos
# ─────────────────────────────────────────────

def solicitar_datos() -> tuple[bytes, bytes, bytes]:
    print("\n┌─────────────────────────────────────────────────┐")
    print("│             INGRESO DE DATOS                    │")
    print("│  Se usarán en los 3 algoritmos: AES, DES, 3DES │")
    print("└─────────────────────────────────────────────────┘")
    print()
    print("  Nota: la key e IV se ajustarán automáticamente")
    print("        al tamaño requerido por cada algoritmo.")
    print()

    clave_raw = input("  Ingresa la clave (key) : ").encode("utf-8")
    iv_raw    = input("  Ingresa el IV          : ").encode("utf-8")
    texto     = input("  Ingresa el texto       : ").encode("utf-8")

    print("\n" + "─" * 51)
    input("  >>> PAUSA 1 — Foto de solicitud de datos. ENTER para continuar...")
    return clave_raw, iv_raw, texto


# ─────────────────────────────────────────────
# SECCIÓN 2 — Validación por algoritmo
# ─────────────────────────────────────────────

def validar_todos(clave_raw: bytes, iv_raw: bytes) -> dict:
    print("\n┌─────────────────────────────────────────────────┐")
    print("│         VALIDACIÓN DE TAMAÑOS                   │")
    print("└─────────────────────────────────────────────────┘")

    claves_ivs = {}
    for algo in ["AES", "DES", "3DES"]:
        cfg = ALGO_CONFIG[algo]
        print(f"\n  [{algo}]  key válida: {cfg['key_sizes']}B  |  IV requerido: {cfg['iv_size']}B")
        print(f"  ── Clave ──")
        clave = ajustar_clave(clave_raw, algo)
        print(f"  ── IV ──")
        iv    = ajustar_iv(iv_raw, algo)
        claves_ivs[algo] = (clave, iv)

    print("\n" + "─" * 51)
    input("  >>> PAUSA 2 — Foto de validación de tamaños. ENTER para continuar...")
    return claves_ivs


# ─────────────────────────────────────────────
# SECCIÓN 3 — Cifrado y descifrado
# ─────────────────────────────────────────────

def cifrar_todos(texto: bytes, claves_ivs: dict):
    print("\n┌─────────────────────────────────────────────────┐")
    print("│         CIFRADO Y DESCIFRADO (modo CBC)         │")
    print("└─────────────────────────────────────────────────┘")
    print(f"\n  Texto original : {texto.decode('utf-8')}\n")

    for algo in ["AES", "DES", "3DES"]:
        clave, iv        = claves_ivs[algo]
        fn_cifrar, fn_dc = CIFRADORES[algo]

        cifrado    = fn_cifrar(texto, clave, iv)
        descifrado = fn_dc(cifrado, clave, iv)

        print(f"  ╔══ {algo} {'═' * (44 - len(algo))}")
        print(f"  ║  Cifrado (hex) : {cifrado.hex()}")
        print(f"  ║  Cifrado (b64) : {base64.b64encode(cifrado).decode()}")
        print(f"  ║  Descifrado    : {descifrado.decode('utf-8')}")
        ok = "✓ Coincide con el original" if descifrado == texto else "✗ ERROR: no coincide"
        print(f"  ╚══ {ok}\n")

    print("═" * 51)
    input("  >>> PAUSA 3 — Foto de cifrado/descifrado. ENTER para finalizar...")


# ─────────────────────────────────────────────
# Flujo principal
# ─────────────────────────────────────────────

def main():
    print("=" * 51)
    print("   CIFRADO / DESCIFRADO — AES | DES | 3DES")
    print("   Mismo texto, key e IV para los 3 algoritmos")
    print("=" * 51)

    clave_raw, iv_raw, texto = solicitar_datos()
    claves_ivs               = validar_todos(clave_raw, iv_raw)
    cifrar_todos(texto, claves_ivs)

    print("\n  Programa finalizado.")

if __name__ == "__main__":
    main()