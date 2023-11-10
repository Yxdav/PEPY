
def info(text: str | None)->None:
    print(f"[*] {text}")

def ok(text: str | None)->None:
    print(f"[+] {text}")

def warning(text: str | None)->None:
    print(f"[!] {text}")

def error(text: str | None)->None:
    print(f"[-] {text}")


